import {Runner} from "./runner.js";
import {addLineNumbers, esc, firstNonEmpty, indent, wrapTripleBackticks} from "../utils/utils.js";
import ApiModule from "../analysis/api-explorer/apiModule.js";
import LocationRange from "../models/locationRange.js";
import {missingDefinitionTool} from "../model/tools.js";
import Location from "../models/location.js";
import CodeQLQueryBuilder from "../analysis/codeql/codeQLQueryBuilder.js";
import ApiFunction from "../analysis/api-explorer/apiFunction.js";
import Source from "../models/source.js";
import {getPrompt} from "../prompting/promptGenerator.js";
import RunnerResult from "./runnerResult.js";

process.on(
   "message",
   async (options) => {
      const runner = new RunnerSourceNotExported(options);
      await runner.start();
      process.send(RunnerResult.prototype.toJSON.apply(runner));
   },
);

export class RunnerSourceNotExported extends Runner {

   /**
    * Given the vulnerability report, query the model to identify if the vulnerability is a remote flow source.
    *
    * @returns {Promise<boolean>} - True if the vulnerability is a remote flow source, false otherwise.
    */
   async isRemoteFlowSource() {
      const prompt = getPrompt("identifyThreatModel", {
         vulnerabilitySummary: this.advisory.summary,
         vulnerabilityDescription: this.vulnerabilityDescription,
      });
      const response = await this.model.queryOne(prompt);
      return this.llmIdentifiedRemoteFlow = response.split("\n")[0].toLowerCase().includes("yes");
   }

   /** @inheritDoc */
   async startExploitCreation() {
      if (this.candidatesByName.length === 0) {
         const isRemoteFlow = await this.isRemoteFlowSource();
         if (isRemoteFlow) {
            const res = await this.createExploitRemoteFlow();
            if (res) {
               return res;
            }
         }
      }
      try {
         const result = await super.startExploitCreation();
         if (result) {
            return result;
         }
      } catch (e) {
         console.error(e)
      }
      if (this.exploitAttempts.length > 0) {
         return null;
      }
      return await this.createExploitRemoteFlow();
   }

   /**
    * Create an exploit for a remote flow source.
    *
    * @returns {Promise<ExploitSuccessResult|null>} - The exploit success result if an exploit was created, null otherwise.
    */
   async createExploitRemoteFlow() {
      const possibleVulnerabilityTypes = await this.identifyVulnerabilityType();

      for (const vulnerabilityType of possibleVulnerabilityTypes) {
         let sarif = this.codeQL.analyse(
            new CodeQLQueryBuilder({
               vulnerabilityType,
               extraSourcePredicate: "source instanceof RemoteFlowSource",
            }), this.apiExplorerResults.sources
         );
         if (sarif.taintPaths.length === 0) {
            sarif = this.codeQL.analyse(
               new CodeQLQueryBuilder({
                  vulnerabilityType,
                  extraSourcePredicate: "source instanceof RemoteFlowSource",
                  taintStepsPrecision: 1,
               }), this.apiExplorerResults.sources
            );
         }
         if (sarif.taintPaths.length === 0) {
            continue;
         }
         console.log(`Found ${sarif.taintPaths.length} taint paths from remote sources`);
         for (const remoteFlowTaintPath of sarif.taintPaths) {
            const fullTaintPaths = await this.enrichTaintPath(vulnerabilityType, remoteFlowTaintPath);
            const sourceGroups = fullTaintPaths.reduce((acc, tp) => {
               if (!acc.has(tp.source)) {
                  acc.set(tp.source, []);
               }
               acc.get(tp.source).push(tp);
               return acc;
            }, new Map());
            for (const [source, taintPaths] of sourceGroups.entries()) {
               for (const tp of taintPaths) {
                  tp.vulnerabilityType = vulnerabilityType;
                  if (tp.source !== source) {
                     throw new Error("invalid state");
                  }
               }
               const exploitSuccessResult = await this.createExploitForSource(
                  source,
                  taintPaths,
               );
               if (exploitSuccessResult) {
                  return exploitSuccessResult;
               }
            }
         }
      }
      return null;
   }

   /**
    * Enrich the taint path with more context.
    *
    * @param {VulnerabilityType} vulnerabilityType - The type of the vulnerability.
    * @param {TaintPath} taintPath - The taint path to enrich.
    * @returns {Promise<TaintPath[]>} - The enriched taint path.
    */
   async enrichTaintPath(vulnerabilityType, taintPath) {
      if (taintPath.source) {
         // Already part of exported
         return [taintPath];
      }

      const resultTaintPaths = [];
      // No exported function
      const sourceFunctionNode = taintPath.functionSnippets[0].functionNodePath;
      const contextNode = taintPath.functionSnippets[0].contextNodePath;
      taintPath.source = this.sourceFrom(sourceFunctionNode, contextNode);

      let isExported = false;
      if (this.apiExplorerResults.sources.length > 0) {
         const fullExportTaintPath = await this.findExportedApi(taintPath);
         if (fullExportTaintPath.length > 0) {
            isExported = true;
            resultTaintPaths.push(...fullExportTaintPath);
         }
      }

      if (!isExported) {
         const sourceContext = await this.getSourceCallContext(taintPath);
         Object.defineProperty(taintPath.source, 'apiCompletion', {
            get: function () {
               return sourceContext;
            },
            configurable: true,
            enumerable: true
         });
         resultTaintPaths.push(taintPath);
      }

      return resultTaintPaths;
   }

   /**
    * Find exported API functions that reference the taint path source.
    *
    * @param {TaintPath} remoteFlowTaintPath - The taint path to check.
    * @returns {Promise<TaintPath[]>} - The list of taint paths that reference the source.
    */
   async findExportedApi(remoteFlowTaintPath) {
      console.info("Checking if exported sources reference taint path source")
      const sink = remoteFlowTaintPath.source;

      const sarifFile = this.codeQL.getCGA(sink, this.apiExplorerResults.sources);
      if (sarifFile.taintPaths.filter(s => s.source).length === 0) {
         return [];
      }

      // Taint paths from exported sources to sink
      const results = [];
      for (const taintPath of sarifFile.taintPaths) {
         if (!taintPath.source) {
            console.warn(
               `(Not exported) Could not map taint path ${taintPath.taintStepLocations} to any source`,
            );
            continue;
         }
         results.push(taintPath.concat(remoteFlowTaintPath));
      }
      return results;
   }

   /**
    * Called when no callgraph from exported callable exists to {@link taintPath.source}
    * This usually means that a call to the source can be triggered once the package is imported
    *
    * @param {TaintPath} taintPath - The taint path to get the context for.
    * @returns {Promise<string>} - The context for the taint path.
    */
   async getSourceCallContext(taintPath) {
      /**
       * @type {LocationRange[]}
       */
      const resolvedLocations = [taintPath.source.callable.location];

      let sourceContextPrompt = "";

      /**
       * List of statements that have been resolved
       * @type {NodePath<Node>[]}
       */
      const seenStatements = [];

      /**
       * List of statements that may contain references and need to be resolved.
       * @type {NodePath<Node>[]}
       */
      const toResolve = [this.codeQL.getEnclosingStatement(taintPath.source.callable.location)];

      while (toResolve.length > 0) {
         const resolveNode = toResolve.pop();
         const stmtLocation = LocationRange.fromBabelNode(resolveNode.node);
         const code = this.codeQL.extractSourceCode(stmtLocation);

         sourceContextPrompt += `Statement executed in ${esc(stmtLocation.filePath + ":" + stmtLocation.startLine)}:\n`;
         sourceContextPrompt += wrapTripleBackticks(code, "js");
         sourceContextPrompt += "\n";

         const prompt = getPrompt("getContext",
            {
               package: this.package,
               toolName: missingDefinitionTool.function.name,
               sourceCode: addLineNumbers(code, stmtLocation.startLine)
            }
         );
         const toolCalls = await this.model.queryTools(prompt, [
            missingDefinitionTool,
         ]);
         for (const toolCall of toolCalls) {
            const {referenceLineNumber, identifierName} = toolCall.arguments;
            const startColumn = this.codeQL
               .getFileLine(stmtLocation.filePath, referenceLineNumber - 1) // The line numbers in the prompt are 1-based
               .indexOf(identifierName); // 0-based
            if (startColumn < 0) {
               console.warn(
                  `Could not find identifier ${identifierName} in line ${referenceLineNumber}`,
               );
               continue;
            }
            const identifierLocation = new Location(
               stmtLocation.filePath,
               referenceLineNumber,
               startColumn + identifierName.length, // Select from end to avoid selecting wrong identifier in case of a MemberExpression
            );
            const references = (await this.codeQL.getReferences(identifierLocation)).filter(ref => this.codeQL.isIndexed(ref.filePath));
            if (references.length > 0) {
               sourceContextPrompt += `Declaration of ${identifierName}:\n`;
               for (const refLocation of references) {
                  sourceContextPrompt += `${wrapTripleBackticks(
                     this.codeQL.extractSourceCode({...refLocation, startColumn: 0, endColumn: Infinity}),
                     "js")}\n`;
               }
            }
         }

         // Function or variable declaration
         const curContextNodeLocation = LocationRange.fromBabelNode(resolveNode.node);
         resolvedLocations.push(curContextNodeLocation);

         const foundReferences = await this.codeQL.getReferences(
            curContextNodeLocation,
         );
         const newReferences = foundReferences.filter(location =>
            // Exclude already resolved locations.
            resolvedLocations.every(resolvedLocation => !LocationRange.equals(resolvedLocation, location)
               // Exclude nodejs modules.
               && this.codeQL.isIndexed(location.filePath)
            ));
         if (newReferences.length === 0) {
            continue;
         }
         for (const refLocation of newReferences) {
            const stmtNode = this.codeQL.getEnclosingStatement(refLocation);
            if (!seenStatements.includes(stmtNode)) {
               toResolve.push(stmtNode);
               seenStatements.push(stmtNode);
            }
         }
      }
      let result = "";
      if (sourceContextPrompt) {
         result += `References to ${taintPath.source.toLLM}:\n`;
         result += sourceContextPrompt;
      }
      if (!result.endsWith("\n")) {
         result += "\n"
      }

      const requireCode = `require("${taintPath.source.module.importName}"); // import vulnerable code in ${esc(taintPath.source.callable.location.filePath)}\n`;
      const code = `async function exploit() {\n${indent("// complete exploit", 3)}\n}\n\n${requireCode}\nawait exploit();`;
      result += `Complete the following code to trigger the vulnerability:\n`;
      result += `${wrapTripleBackticks(code)}\n`;

      return result;
   }

   /**
    * Create a Source object from an ApiFunction object.
    *
    * @param {NodePath} nodePath - The Babel AST node path of the function.
    * @param {NodePath?} contextNodePath - The Babel AST node path of the context node.
    * @returns {Source} - The Source object created from the ApiFunction.
    */
   sourceFrom(nodePath, contextNodePath = undefined) {
      const location = LocationRange.fromBabelFunctionNode(nodePath.node);
      let module = this.apiExplorerResults.list.map(s => s.apiModule).find((module) => module.relativePath === location.filePath);
      if (!module) {
         module = ApiModule.fromFile(this.package, location.filePath);
      }
      const functionName = firstNonEmpty(nodePath.node.id?.name, contextNodePath?.node.id?.name, "anonymous");

      const code = this.codeQL.extractSourceCode(location);
      const apiFunction = new ApiFunction(
         code,
         functionName,
         location,
         undefined,
         nodePath.node,
         [],
      );
      return new Source(
         [],
         apiFunction,
         module,
         false,
         false,
      );
   }

}

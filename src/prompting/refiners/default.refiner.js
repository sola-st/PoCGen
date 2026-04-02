import { getPrompt, renderPromptTemplate } from "../promptGenerator.js";
import { TaintPathSummarizer } from "../taintPathSummarizer.js";
import SummarizerOptions from "../summarizerOptions.js";
import { Prompt } from "../prompt.js";
import Location from "../../models/location.js";
import BreakpointRequest from "../../models/breakpointRequest.js";
import { MessageType } from "../../analysis/oracle/validators/validator.js";
import { debugRequestsTool, missingDefinitionTool } from "../../model/tools.js";
import MissingDeclarationsSnippet from "../../analysis/codeql/missingDeclarationsSnippet.js";
import { wrapBackticks } from "../../utils/utils.js";
import fs from "fs";
import { join } from "node:path";

export default class DefaultRefiner {

   /**
    * @type {number}
    */
   round;

   /**
    * @type {number}
    */
   priority;

   /**
    * @type {Runner}
    */
   runner;

   /**
    * List of hit breakpoints.
    * @type {HitBreakpoint[]}
    */
   hitBreakpoints;

   /**
    * @type {TaintPath}
    */
   taintPath;

   /**
    * @type {Source}
    */
   source;

   /**
    * @type {RuntimeInfo}
    */
   runtimeInfo;

   /**
    * @param {RefinementInfo} refinementInfo
    * @param {RefinementOptions} refinementOptions
    */
   constructor(refinementInfo, refinementOptions) {
      this.refinementInfo = refinementInfo;
      this.refinementOptions = refinementOptions;
      this.runtimeInfo = refinementInfo?.runtimeInfo;

      const promptRefiner = refinementInfo?.promptRefiner;

      this.promptRefiner = promptRefiner;
      this.taintPath = promptRefiner.taintPath;
      this.stoppedSnippet = this.refinementInfo?.stoppedFunction;
      this.source = this.taintPath.source;
      this.package = promptRefiner.npmPackage;
      this.runner = promptRefiner.runner;
      this.model = promptRefiner.runner.model;
      this.vulnerabilityDescription = this.promptRefiner.vulnerabilityDescription;
      this.vulnerabilityType = this.promptRefiner.taintPath.vulnerabilityType;
      if (!this.vulnerabilityType) {
         throw new Error("Vulnerability type not set");
      }
      this.codeQL = promptRefiner.taintPath.sarifFile.codeQL;
   }

   async refine() {
      this.renderVars = {
         vulnerabilityType: this.vulnerabilityType,
         vulnerabilityDescription: this.vulnerabilityDescription,
         package: this.package,
         source: this.source,
      }

      if (this.refinementOptions.includeSimilarExploits) {
         this.renderVars.similarExploits = this.promptRefiner.similarExploits;
      }
      if (this.refinementOptions.includeApiReferences) {
         this.renderVars.apiReferences = this.promptRefiner.taintPath.source.snippets;
      }
      if (this.refinementOptions.includeApiCompletion) {
         this.renderVars.apiCompletion = this.source.apiCompletion;
      }

      if (this.refinementOptions.includeError && this.runtimeInfo?.errors.length > 0) {
         const errors = [];
         for (const error of this.runtimeInfo.errors) {
            if (error.stack) {
               errors.push(error.stack);
               console.log(`[Runtime error] length: ${error.stack.length}`);
            } else {
               errors.push(error);
               console.log(`[Runtime error] length: ${error.length}`);
            }
         }
         this.renderVars.errors = errors;
      }

      if (this.refinementOptions.includeRefinementMessages && this.runtimeInfo?.refineMessages.length > 0) {
         this.renderVars.refinementMessages = this.runtimeInfo.refineMessages.join("\n")
      }

      if (this.runtimeInfo) {
         this.renderVars.failedExploit = this.refinementInfo.failedExploit;

         if (this.refinementOptions.includeConsoleMessages) {
            this.renderVars.consoleMessages = this.runtimeInfo.consoleMessages;
            console.log(`[Console messages] length: ${this.runtimeInfo.consoleMessages.length}`);
         }
      }

      if (this.refinementOptions.resolveReferences) {
         // const stoppedFunction = this.stoppedSnippet?.functionSnippet ?? this.taintPath.getSinkFunctionSnippet();

         // if (this.refinementOptions.verbosity === SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS) {
         //    /**
         //     * Resolves missing references for the entire taint path.
         //     */
         //    for (const functionSnippet of this.promptRefiner.taintPath.functionSnippets) {
         //       this.taintPath.missingDeclarations.put(await this.resolveMissingDeclarations(functionSnippet));
         //    }
         // } else {
         //    // If flow stops at a function, resolve references for that function.
         //    this.taintPath.missingDeclarations.put(await this.resolveMissingDeclarations(stoppedFunction));
         // }
         for (const functionSnippet of this.promptRefiner.taintPath.functionSnippets) {
            this.taintPath.missingDeclarations.put(await this.resolveMissingDeclarations(functionSnippet));
         }
      }

      if (this.refinementOptions.setBreakPoints) {
         // const stoppedFunction = this.stoppedSnippet?.functionSnippet ?? this.taintPath.getSinkFunctionSnippet();
         // this.hitBreakpoints = await this.getBreakPoints(stoppedFunction);
         this.hitBreakpoints = [];
         for (const functionSnippet of this.promptRefiner.taintPath.functionSnippets) {
            this.hitBreakpoints.push(...(await this.getBreakPoints(functionSnippet)));
         }
      }

      try {
         const sysPrompt = this.getSystemPrompt();
         const taintPathSnippets = this.getTaintPathSnippets();
         const userPrompt = renderPromptTemplate(`exploitCreation/${this.runtimeInfo ? "create" : "seed"}.user`, {
            ...this.renderVars,
            taintPathSnippets,
         });
         return this.prompt = new Prompt(sysPrompt, userPrompt);
      } catch (e) {
         console.warn("Error refining prompt");
         console.error(e);
      }
      return null;
   }

   getTaintPathSnippets() {
      /**
       * @type {TaintPathSummarizerParams}
       */
      const taintPathOpts = {
         taintPath: this.taintPath,
         hitBreakPoints: this.hitBreakpoints,
         missingDeclarations: this.taintPath.missingDeclarations,
      };

      if (this.refinementOptions.includeError) {
         taintPathOpts.options = new SummarizerOptions(true, this.refinementOptions.verbosity);
         taintPathOpts.errorDetails = this.refinementInfo.runtimeInfo?.errors.filter(e => e.stackFrames);
      } else {
         taintPathOpts.options = new SummarizerOptions(false, this.refinementOptions.verbosity);
      }

      if (this.refinementOptions.includeCoverage) {
         taintPathOpts.stoppedSnippet = this.stoppedSnippet;
         taintPathOpts.uncoveredLocations = this.refinementInfo.uncoveredLocations;
      }

      return new TaintPathSummarizer(taintPathOpts).complete();
   }

   /**
    * @param {FunctionSnippet} functionSnippet
    * @returns {Promise<HitBreakpoint[]>}
    */
   async getBreakPoints(functionSnippet) {
      if (!this.refinementInfo?.failedExploit) {
         throw new Error("Failed exploit not set");
      }
      const existing = this.refinementInfo.sharedDebugExpressions.find(
         (shared) => shared.functionSnippet === functionSnippet,
      );
      if (existing) {
         return existing.breakPoints;
      }
      const breakPoints = [];
      this.refinementInfo.sharedDebugExpressions.push({
         functionSnippet,
         breakPoints,
      });
      const debugRequests = await this.getDebugRequestsLLM(functionSnippet);
      if (debugRequests?.length > 0) {
         const bp = (await this.runner.oracle({
            type: MessageType.DEBUG,
            content: {
               baseDir: this.runner.baseDir,
               nmPath: this.runner.nmPath,
               nmModulePath: this.runner.nmModulePath,
               source: this.taintPath.source,
               exploit: this.refinementInfo.failedExploit,
               vulnerabilityTypeLabel: this.vulnerabilityType.label,
               debugRequests,
            },
         }, this.vulnerabilityType)).hitBreakpoints;
         breakPoints.push(...bp);
      }
      return breakPoints;
   }

   /**
    * @param {FunctionSnippet} functionSnippet
    * @returns {Promise<BreakpointRequest[]>}
    */
   async getDebugRequestsLLM(functionSnippet) {
      const uncoveredLocations = this.refinementInfo.uncoveredLocations;
      let taintPathSnippets;
      if (uncoveredLocations) {
         taintPathSnippets =
            `The lines prefixed with "-" were not executed.\n` + new TaintPathSummarizer({
               taintPath: this.taintPath,
               options: new SummarizerOptions(true, SummarizerOptions.SnippetVerbosity.FULL_BODY),
               uncoveredLocations
            }).getBody(functionSnippet);
      } else {
         taintPathSnippets = new TaintPathSummarizer({
            taintPath: this.taintPath,
            options: new SummarizerOptions(true, SummarizerOptions.SnippetVerbosity.FULL_BODY),
            errorDetails: this.refinementInfo.errorDetails
         }).getBody(functionSnippet);
      }
      const prompt = getPrompt("getBreakPointRequests", {
         toolName: debugRequestsTool.function.name,
         failedExploit: this.refinementInfo.failedExploit,
         vulnerabilityType: this.vulnerabilityType,
         taintPathSnippets,
      })

      /**
       * @type {BreakpointRequest[]}
       */
      const breakPointRequests = [];

      try {
         /**
          * @type {FunctionCall[]}
          */
         const calls = await this.model.queryTools(prompt, [debugRequestsTool]);
         const functionLocation = functionSnippet.location;
         for (const call of calls) {
            const breakLocation = new Location(functionLocation.filePath, call.arguments.lineNumber, functionLocation.startColumn);
            breakPointRequests.push(new BreakpointRequest(breakLocation, call.arguments.expression));
         }
      } catch (e) {
         console.error(e)
      }
      return breakPointRequests;
   }

   /**
    * Resolves references for a given function snippet within the taint path.
    *
    * @param {FunctionSnippet} functionSnippet - The function snippet for which to resolve references.
    * @returns {Promise<MissingDeclarationsSnippet>} The missing declarations snippet
    */
   async resolveMissingDeclarations(functionSnippet) {
      const existing = this.taintPath.missingDeclarations.get(functionSnippet);
      if (existing) {
         return existing;
      }
      const missingDeclarationsSnippet = new MissingDeclarationsSnippet(functionSnippet);
      this.taintPath.missingDeclarations.put(missingDeclarationsSnippet);
      const declarationsSoFar = [
         new TaintPathSummarizer({
            taintPath: this.taintPath,
            options: new SummarizerOptions(
               true,
               SummarizerOptions.SnippetVerbosity.FULL_BODY,
            ),
         }).getBody(functionSnippet),
      ];
      const callExpressionNode = functionSnippet.findTaintCallExpression();
      let callExpression;
      if (callExpression) {
         callExpression = `the call to ${wrapBackticks(this.codeQL.extractSourceCodeNode(callExpressionNode))} in line ${callExpressionNode.loc.start.line}`;
      } else {
         callExpression = `${this.codeQL.extractSourceCode(functionSnippet.getLastTaintStepLocation())} in line ${functionSnippet.getLastTaintStepLocation().startLine}`;
      }
      const prompt = getPrompt("resolveReferences", {
         callExpression,
         toolName: missingDefinitionTool.function.name,
         package: this.package,
         snippets: declarationsSoFar
      })
      const toolCalls = await this.model.queryTools(prompt, [
         missingDefinitionTool,
      ]);
      for (const toolCall of toolCalls) {
         const { referenceLineNumber, identifierName } = toolCall.arguments;
         const startColumn = this.codeQL
            // The line numbers in the prompt are 1-based
            .getFileLine(functionSnippet.getFile(), referenceLineNumber - 1)
            // 0-based
            .indexOf(identifierName);
         if (startColumn < 0) {
            console.warn(
               `Could not find identifier ${identifierName} in line ${referenceLineNumber}`,
            );
            continue;
         }
         const identifierLocation = new Location(
            functionSnippet.getFile(),
            referenceLineNumber,
            // Select from end to avoid selecting wrong identifier in case of a MemberExpression
            startColumn + identifierName.length,
         );
         if (!missingDeclarationsSnippet.hasDeclaration(identifierLocation)) {
            const locations =
               await this.codeQL.getDefinitions(identifierLocation);
            missingDeclarationsSnippet.addDeclaration(
               identifierName,
               identifierLocation,
               locations,
            );
         }
      }
      return missingDeclarationsSnippet;
   }

   getSystemPrompt() {
      const vars = {
         vulnerabilityType: this.vulnerabilityType,
      }
      if (this.refinementOptions?.includeCWE) {
         try {
            vars.cweDescription = fs.readFileSync(join(import.meta.dirname, "..", "prompts", "cwe", `${this.vulnerabilityType.label}.md`), "utf-8");
         } catch (_) {
         }
      }
      return renderPromptTemplate("exploitCreation/system", vars);
   }

   toJSON() {
      return {
         name: this.constructor.name,
         refinementOptions: this.refinementOptions,
      };
   }
}

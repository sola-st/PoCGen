import LocationRange from "../models/locationRange.js";
import {
   addLineNumbers,
   extractSourceCode,
   firstNonEmpty,
   joinTexts,
   truncateString,
   wrapBackticks,
   wrapTripleBackticks,
} from "../utils/utils.js";
import { getSignature } from "../utils/parserUtils.js";
import SummarizerOptions from "./summarizerOptions.js";
import { relative } from "node:path";
import { readFileSync } from "node:fs";
import { parseExpression } from "@babel/parser";

const SNIP = "<snip>";

/**
 * @typedef {Object} TaintPathSummarizerParams
 * @property {TaintPath} taintPath - The taint path to summarize.
 * @property {SummarizerOptions} [options] - The summarizer options.
 * @property {HitBreakpoint[]} [hitBreakPoints] - The hit breakpoints encountered.
 * @property {ErrorDetails[]} [errorDetails] - The list of error details.
 * @property {MissingDeclarations} [missingDeclarations] - The missing declarations.
 * @property {LocationRange[]} [uncoveredLocations] - The uncovered locations.
 * @property {StoppedFunction} [stoppedSnippet] - The stopped function snippet.
 */

/**
 * @typedef {import("../../node_modules/stacktrace-parser/dist/stack-trace-parser.js").StackFrame} StackFrame
 * @typedef {import("../models/runtimeInfo.js").ErrorDetails} ErrorDetails
 */
export class TaintPathSummarizer {

   /**
    * The function snippet where the taint path stopped.
    * @type {StoppedFunction|null}
    */
   stoppedSnippet;

   /**
    * @type {LocationRange[]}
    */
   uncoveredLocations;

   /**
    * Initializes a new instance of the TaintPathSummarizer class.
    *
    * @param {TaintPathSummarizerParams} params - The summarizer parameters.
    */
   constructor({
      taintPath,
      options = undefined,
      hitBreakPoints = undefined,
      errorDetails = undefined,
      missingDeclarations = undefined,
      uncoveredLocations = undefined,
      stoppedSnippet,
      maxTokens = 80_000
   }) {
      this.maxTokens = maxTokens;
      this.taintPath = taintPath;
      this.options = options;
      this.hitBreakPoints = hitBreakPoints;
      this.errorDetails = errorDetails;
      this.missingDeclarations = missingDeclarations;
      this.stoppedSnippet = stoppedSnippet;
      this.uncoveredLocations = uncoveredLocations;
   }

   /**
    * @returns {string}
    */
   complete() {
      let prompt = "";

      if (this.uncoveredLocations) {
         prompt += `The lines prefixed with "-" were not executed.\n`
      }

      const source = this.taintPath.source;
      const constructor = source.getConstructor();
      if (constructor) {
         prompt += `constructor ${wrapBackticks(source.getParentClass().name)} of ${wrapBackticks(source.name)} located in ${constructor.location.filePath}:\n`;
         if (this.options?.verbosity === 0) {
            prompt += `${wrapTripleBackticks(constructor.signature)}\n`;
         } else {
            prompt += `${wrapTripleBackticks(constructor.code)}\n`;
         }
      }
      for (let snippetIdx = 0; snippetIdx < this.taintPath.functionSnippets.length; snippetIdx++) {
         prompt += `${(this.getSummary(this.taintPath.functionSnippets, snippetIdx))}\n`;
      }
      console.log(`[Analysis Info] length: ${prompt.length}`);
      return prompt.trimEnd();
   }

   /**
    * Generates a summary for a specific function snippet.
    *
    * @param {FunctionSnippet[]} snippets - The array of function snippets.
    * @param {number} snippetIdx - The index of the current snippet.
    * @returns {string} The generated snippet summary.
    */
   getSummary(snippets, snippetIdx) {
      return joinTexts("\n",
         this.getHeader(snippets, snippetIdx),
         wrapTripleBackticks(this.getBody(snippets[snippetIdx]), "js"),
         this.getFooter(snippets[snippetIdx])
      );
   }

   /**
    * Generates the header for a function snippet.
    * The header summarizes how the snippet relates to the previous and next snippet.
    *
    * @param {FunctionSnippet[]} snippets - The array of function snippets.
    * @param {number} snippetIdx - The index of the current snippet.
    * @returns {string} The generated header.
    */
   getHeader(snippets, snippetIdx) {
      let header = "";
      const curSnippet = snippets[snippetIdx];

      if (snippetIdx === 0) {
         header = `Vulnerable ${(this.taintPath.source.toLLM)} located in ${curSnippet.stepLocations[0].filePath}`;
      } else {
         const prevSnippet = snippets[snippetIdx - 1];
         const returnSnippet = snippets
            .slice(0, snippetIdx)
            .findLast((snippet) => LocationRange.equals(snippet.location, curSnippet.location));

         if (returnSnippet) {
            header = `Flow returns to ${(returnSnippet.toLLM)}`;
         } else {
            const prevLastStep = prevSnippet.getLastTaintStepLocation();
            const callExpr = prevSnippet.findCallExpression(prevLastStep);
            if (callExpr) {
               const taintStepNodeSource = this.taintPath.sarifFile.codeQL.extractSourceCode(
                  LocationRange.fromBabelNode(prevSnippet.findCallExpression(prevLastStep)),
               );
               try {
                  const callExprParsed = parseExpression(taintStepNodeSource,
                     {
                        errorRecovery: true,
                     }
                  );
                  if (callExprParsed.type === "CallExpression") {
                     let fname = "";
                     fname = taintStepNodeSource.slice(0, callExprParsed.callee.end)
                     header = `Call to ${wrapBackticks(fname)}`;
                  }
               } catch (e) {
               }
               if (!header) {
                  header = `Call to ${wrapBackticks(taintStepNodeSource)}`;
               }
               // header += ` in line ${prevLastStep.startLine}`;
            } else {
               console.warn("no call expression found");
               header = `Call to ${(curSnippet.toLLM)}`;
            }
         }
      }
      if (this.stoppedSnippet && curSnippet === this.stoppedSnippet.functionSnippet) {
         if (this.stoppedSnippet.entireFunctionNotExecuted) {
            header += ` (the entire function was not executed)`;
         } else {
            header += ` (the flow stops here)`;
         }
      }
      header = header ? `${header}:\n` : "";
      return header;
   }

   /**
    * Generates the body of a function snippet.
    *
    * @param {FunctionSnippet} functionSnippet - The function snippet to generate the body for.
    * @param {number?} verbosity - The verbosity level for the snippet body.
    * @param {LocationRange?} range - The specific range within the function snippet to include in the body.
    * @returns {string} The generated snippet body.
    */
   getBody(functionSnippet, verbosity = undefined, range = undefined) {
      let body;
      if (range) {
         body = this.#getSnippetRange(functionSnippet, range);
      } else {
         switch (verbosity ?? this.options.verbosity) {
            case SummarizerOptions.SnippetVerbosity.CONTEXT:
               body = this.#getSnippetContext(functionSnippet);
               break;
            case SummarizerOptions.SnippetVerbosity.FULL_BODY:
            case SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS:
               body = this.#getSnippetFullBody(functionSnippet);
               break;
            default:
               throw new Error("Invalid value");
         }
      }
      if (this.options.includeFunctionComments && functionSnippet.leadingCommentsRange) {
         const leadingCommentsRange = functionSnippet.leadingCommentsRange;
         // Dont include line numbers for comments, even if the option is set
         const comments = this.taintPath.sarifFile.codeQL.extractSourceCode(leadingCommentsRange);
         body = `${comments}\n${body}`;
      }
      return body;
   }

   /**
    * Generates the footer for a function snippet.
    * The footer includes any missing declarations for the function snippet and debug information.
    *
    * @param {FunctionSnippet} functionSnippet - The function snippet to generate the footer for.
    * @returns {string} The generated footer.
    */
   getFooter(functionSnippet) {
      let footer = "";
      const missingDeclarationsSnippet = this.missingDeclarations?.get(functionSnippet);
      if (
         this.options.verbosity ===
         SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS
         && missingDeclarationsSnippet
      ) {
         const declarations = [];
         for (const declaration of Object.values(missingDeclarationsSnippet.declarations)) {
            for (const declareLocation of declaration.locations) {
               if (this.taintPath.contains(declareLocation)) {
                  // Skip declarations that are part of the taint path
                  continue;
               }
               if (declareLocation.filePath.startsWith("/")) {
                  // This can happen when the LLM asks for a declaration located in a different library.
                  const baseDir = this.taintPath.sarifFile.codeQL.baseDir;
                  if (declareLocation.filePath.startsWith(baseDir)) {
                     let prompt = `Declaration of ${wrapBackticks(declaration.identifierName)} referenced at ${declaration.referenceLocation.toString()}:\n`;
                     prompt += `Defined in ${relative(baseDir, declareLocation.filePath)}:\n`;
                     prompt += `${wrapTripleBackticks(extractSourceCode(declareLocation, readFileSync(declareLocation.filePath, "utf-8")), "js")}\n`;
                     declarations.push(prompt);
                  } else {
                     console.warn(
                        `Ignoring reference to ${declaration.identifierName} in ${declareLocation.filePath} because it is not in the base directory ${baseDir}`,
                     );
                  }
               } else {
                  let prompt = `Declaration of ${wrapBackticks(declaration.identifierName)} referenced at ${declaration.referenceLocation.toString()}:\n`;
                  prompt += `${wrapTripleBackticks(this.taintPath.sarifFile.codeQL.extractSourceCode(declareLocation), "js")}\n`;
                  declarations.push(prompt);
               }
            }
         }
         if (declarations.length > 0) {
            footer += `With the following declarations:\n`;
            footer += declarations.join("\n");
         }
      }
      if (this.hitBreakPoints?.length > 0) {
         const breakpoints = this.hitBreakPoints.filter(hp =>
            functionSnippet.location.contains(hp.breakpointRequest.location) && hp.runtimeObject.type === "function"
         );
         if (breakpoints.length > 0) {
            footer += `The following breakpoints were hit:\n`;
            for (const hp of breakpoints) {
               footer += `Line ${hp.breakpointRequest.location.startLine}:\n`;
               footer += `Result of ${wrapBackticks(hp.breakpointRequest.expression)}:\n`;
               footer += `${wrapBackticks(truncateString(firstNonEmpty(hp.runtimeObject.value, hp.runtimeObject.description), Infinity))}\n`;
            }
         }
      }
      return footer;
   }

   /**
    * @param {FunctionSnippet} functionSnippet
    * @returns {string}
    */
   #getSnippetContext(functionSnippet) {
      let result = "";
      let prevLocationContext;
      const stepLocations = functionSnippet.stepLocations;
      const codeQL = this.taintPath.sarifFile.codeQL;
      const contextLines = this.options.contextLines;

      // To provide context to the LLM, include signature if it would not be included in the snippet.
      if (
         stepLocations[0].startLine - functionSnippet.location.startLine >
         contextLines
      ) {
         const signature = getSignature(
            functionSnippet.functionNode,
            codeQL.extractSourceCode(functionSnippet.location),
         );
         if (this.options.includeLineNumbers) {
            result = addLineNumbers(
               signature,
               functionSnippet.location.startLine,
            );
         } else {
            result = signature;
         }
         const fnStart = functionSnippet.location.startLine + signature.split("\n").length;
         if (fnStart < stepLocations[0].startLine - contextLines) {
            result += `\n${SNIP}`;
         }
         result += "\n";
      }

      for (const stepLocation of stepLocations) {
         // Add surrounding lines
         const snippetStartLine = Math.max(
            stepLocation.startLine - contextLines,
            functionSnippet.functionNode.loc.start.line,
         );
         const snippetEndLine = Math.min(
            stepLocation.endLine + contextLines,
            functionSnippet.functionNode.loc.end.line,
         );
         const stepLocationContext = new LocationRange(
            stepLocation.filePath,
            snippetStartLine,
            0,
            snippetEndLine,
            Infinity,
         );

         // Remove the part that intersects with the previous snippet
         if (prevLocationContext && prevLocationContext.filePath === stepLocationContext.filePath
         ) {
            if (stepLocationContext.startLine <= prevLocationContext.endLine
               && stepLocationContext.startLine >= prevLocationContext.startLine) {
               // Overlaps with ending of previous snippet
               stepLocationContext.startLine = prevLocationContext.endLine + 1;
            }
            if (stepLocationContext.endLine >= prevLocationContext.startLine
               && stepLocationContext.endLine <= prevLocationContext.endLine) {
               // Overlaps with beginning of previous snippet
               stepLocationContext.endLine = prevLocationContext.startLine - 1;
            }
         }
         if (stepLocationContext.startLine === stepLocationContext.endLine) {
            stepLocationContext.endColumn = Infinity;
         }
         if (!stepLocationContext.isValid()) {
            continue;
         }
         let currentContextStepSource;
         if (this.options.includeLineNumbers) {
            currentContextStepSource = addLineNumbers(
               codeQL.extractSourceCode(stepLocationContext),
               stepLocationContext.startLine,
            );
         } else {
            currentContextStepSource =
               codeQL.extractSourceCode(stepLocationContext);
         }
         // Add "tainted" comments to lines with taint steps
         let annotatedSource = "";
         let lineIdx = stepLocationContext.startLine;
         for (const curLineNumber of currentContextStepSource.split("\n")) {
            annotatedSource += this.#getAnnotateLine(
               functionSnippet,
               curLineNumber,
               lineIdx,
               stepLocations,
            );
            lineIdx++;
         }

         // Add "<snip>" to indicate that the snippet is not a continuation of the previous one
         if (
            prevLocationContext &&
            prevLocationContext.filePath === stepLocationContext.filePath &&
            prevLocationContext.endLine + 1 === stepLocationContext.startLine
         ) {
            // Continuation of the previous snippet
         } else if (prevLocationContext) {
            // annotatedSource += `${SNIP}\n`;
            annotatedSource = `${SNIP}\n${annotatedSource}`;
         }
         result += annotatedSource;
         prevLocationContext = new LocationRange(
            stepLocation.filePath,
            snippetStartLine,
            0,
            snippetEndLine,
            Infinity,
         );
      }
      return result;
   }

   /**
    * Annotates a line of code with comments indicating taint steps, breakpoints, and errors.
    *
    * @param {FunctionSnippet} functionSnippet - The function snippet containing the line of code.
    * @param {string} line - The line of code to annotate.
    * @param {number} lineNumber - The line number of the code.
    * @param {LocationRange[]} taintStepLocations - The locations of taint steps within the function.
    * @returns {string} The annotated line of code.
    */
   #getAnnotateLine(functionSnippet, line, lineNumber, taintStepLocations) {
      const lineComments = [];

      if (this.errorDetails?.length > 0) {
         const lineErrors = this.errorDetails.filter(err =>
            err.stackFrames?.some(sf => sf.lineNumber === lineNumber && sf.file === functionSnippet.location.filePath),
         );
         if (lineErrors.length > 0) {
            let summary = lineErrors.map(err => err.message).join(", ");
            if (summary.length > 0) {
               summary = `throws error: ${wrapBackticks(summary)}`;
               lineComments.push(summary);
            }
         }
      }

      if (this.hitBreakPoints?.length > 0) {
         console.log("breakpoints", JSON.stringify(this.hitBreakPoints));
         const breakPoints = this.hitBreakPoints.filter(hp =>
            hp.breakpointRequest.location.startLine === lineNumber
            && hp.breakpointRequest.location.filePath === taintStepLocations[0].filePath
         );
         if (breakPoints.length > 0) {
            const summary = breakPoints.filter(hit => hit.runtimeObject.type !== "function").map(hit => `value of ${wrapBackticks(hit.breakpointRequest.expression)}: ${wrapBackticks(truncateString(firstNonEmpty(hit.runtimeObject.value, hit.runtimeObject.description), 300))}`).join(", ");
            if (summary.length > 0) {
               lineComments.push(summary);
            }
         }
      }

      let annotatedLine = line;
      if (this.options.taintComments) {
         // Is there a taint step in this line?
         const stepLocationRanges = taintStepLocations.filter(
            (step) => step.startLine === lineNumber && step.endLine === lineNumber,
         );
         if (stepLocationRanges.length > 0) {
            const stepSnippet = this.taintPath.sarifFile.codeQL.extractSourceCode(
               stepLocationRanges[0],
            );
            const summary = `tainted: ${JSON.stringify(stepSnippet)}`;
            lineComments.push(summary);
         }
      }

      if (lineComments.length > 0) {
         annotatedLine += ` // ${lineComments.join(", ")}`;
      }

      if (this.uncoveredLocations?.length > 0) {
         const lineLocation = new LocationRange(
            functionSnippet.location.filePath,
            lineNumber,
            0,
            lineNumber,
            0,
         );
         if (this.uncoveredLocations.some((uncovered) => uncovered.filePath === lineLocation.filePath && uncovered.contains(lineLocation))) {
            annotatedLine = `- ${annotatedLine}`;
         } else {
            annotatedLine = `  ${annotatedLine}`;
         }
      }

      annotatedLine += "\n";
      return annotatedLine;
   }

   /**
    * @param {FunctionSnippet} functionSnippet
    * @param {LocationRange} locationRange
    */
   #getSnippetRange(functionSnippet, locationRange) {
      let functionSource =
         this.taintPath.sarifFile.codeQL.extractSourceCode(locationRange);
      if (this.options.includeLineNumbers) {
         functionSource = addLineNumbers(functionSource, locationRange.startLine);
      }
      const stepLocations = functionSnippet.stepLocations;
      let result = "";
      let curLineNumber = locationRange.startLine;
      for (const line of functionSource.split("\n")) {
         result += this.#getAnnotateLine(functionSnippet, line, curLineNumber, stepLocations);
         curLineNumber++;
      }
      return result;
   }

   /**
    * @param {FunctionSnippet} functionSnippet
    * @returns {string}
    */
   #getSnippetFullBody(functionSnippet) {
      const snippetLocationRange = LocationRange.fromBabelNode(
         functionSnippet.contextNodePath.node,
      );
      return this.#getSnippetRange(functionSnippet, snippetLocationRange);
   }

   /**
    * @param {FunctionSnippet} functionSnippet
    * @returns {string}
    */
   getBodyTilLastTaintStep(functionSnippet) {
      const lastStep = functionSnippet.getLastTaintStepLocation();
      const locationRange = new LocationRange(
         functionSnippet.location.filePath,
         functionSnippet.location.startLine,
         functionSnippet.location.startColumn,
         lastStep.endLine,
         Infinity, // Include the entire line
      );
      return this.getBody(functionSnippet, 0, locationRange);
   }

   /**
    * Returns a string that prefixes the source code of a function snippet with "-" for lines that were not executed.
    *
    * @param {FunctionSnippet} functionSnippet
    * @param {LocationRange[]} uncoveredLocations
    * @returns {string}
    */
   prefixCoveredLinesForSnippet(functionSnippet, uncoveredLocations) {
      const lines = this.taintPath.sarifFile.codeQL
         .extractSourceCode(functionSnippet.getLocationRangeWithComments())
         .split("\n");
      const startLineOffset = functionSnippet.getLocationRangeWithComments().startLine;

      // Prefix all lines that were not executed with "-"
      let prompt = "Lines prefixed with \"-\" were not executed:\n";
      let curLine = startLineOffset;
      for (const line of lines) {
         const lineLocation = new LocationRange(
            functionSnippet.getLocationRangeWithComments().filePath,
            curLine,
            0,
            curLine,
            Infinity,
         );
         let annotatedLine;
         if (uncoveredLocations.some((uncovered) => uncovered.filePath === lineLocation.filePath && uncovered.contains(lineLocation))) {
            annotatedLine = `- ${line}\n`;
         } else {
            annotatedLine = `  ${line}\n`;
         }
         // Prefix line number
         if (this.options.includeLineNumbers) {
            annotatedLine = `${curLine}. ${annotatedLine}`;
         }
         prompt += annotatedLine;
         curLine++;
      }
      return prompt;
   }

}

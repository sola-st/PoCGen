import LocationRange, {containsPoint} from "../../models/locationRange.js";
import FunctionSnippet from "./functionSnippet.js";
import StoppedFunction from "../coverage/stoppedFunction.js";
import {getAllFunctions, getCallExpressionNodes,} from "../../utils/parserUtils.js";
import PotentialSink from "./potentialSink.js";
import {esc} from "../../utils/utils.js";
import MissingDeclarations from "./missingDeclarations.js";

/**
 * @typedef {import("../../models/source").default} Source
 */

export class TaintPath {
   taintStepsPrecision;

   /**
    * Get the location of each step of the taint path
    * @type {LocationRange[]}
    */
   taintStepLocations = undefined;

   /**
    * @type {FunctionSnippet[]}
    */
   #cachedFunctionSnippets = undefined;

   missingDeclarations = new MissingDeclarations();

   /**
    * @type {VulnerabilityType}
    */
   vulnerabilityType;

   /**
    * @param {SarifFile} sarifFile
    * @param {Source} source
    * @param {object} codeFlow
    * @param {PotentialSink[]|undefined} llmSinks
    * @param {LocationRange[]|undefined} taintStepLocations
    */
   constructor(sarifFile, source, codeFlow, llmSinks = undefined, taintStepLocations = undefined) {
      this.sarifFile = sarifFile;
      this.source = source;
      this.llmSinks = llmSinks;
      if (taintStepLocations) {
         this.taintStepLocations = taintStepLocations;
      } else {
         this.taintStepLocations = [];
         const locations = codeFlow.threadFlows[0].locations;
         for (let i = 0; i < locations.length; i++) {
            this.taintStepLocations.push(
               LocationRange.fromCodeQL(locations[i].location.physicalLocation),
            );
         }
      }
      // Restrict to own codebase
      /*  this.taintStepLocations = this.taintStepLocations.filter((loc) =>
           loc.filePath.startsWith(sarifFile.codeQL.npmPackage.asPath()),
        );*/
   }

   /**
    * @returns {PotentialSink}
    */
   getSink() {
      const sinkSnippet = this.getSinkFunctionSnippet();
      const sinkLocation = sinkSnippet.getLastTaintStepLocation();
      let src;
      let locationCallNode;
      try {
         src = this.sarifFile.codeQL.extractSourceCode(sinkLocation);
         const callExpressions = getCallExpressionNodes(
            this.sarifFile.codeQL.parse(sinkLocation.filePath),
         );
         const sinkCallNode = callExpressions.findLast((node) =>
            LocationRange.fromBabelNode(node).contains(sinkLocation),
         );
         if (sinkCallNode) {
            locationCallNode = LocationRange.fromBabelNode(
               sinkCallNode.callee?.property ?? sinkCallNode.callee,
            );
            src = this.sarifFile.codeQL.extractSourceCodeNode(sinkCallNode);
         }
      } catch (e) {
         console.warn(`Could not parse source code as callExpression`);
         console.error(e);
      }
      return new PotentialSink(sinkLocation, locationCallNode, src);
   }

   /**
    * @returns {FunctionSnippet}
    */
   getSinkFunctionSnippet() {
      const snippets = this.functionSnippets;
      return snippets[snippets.length - 1];
   }

   /**
    * Getter for function snippets.
    * Parses the source code and extracts function snippets that contain taint step locations.
    * @returns {FunctionSnippet[]} Array of function snippets.
    */
   get functionSnippets() {
      if (!this.#cachedFunctionSnippets) {
         this.#cachedFunctionSnippets = [];
         for (const stepLocation of this.taintStepLocations) {
            const ast = this.sarifFile.codeQL.parse(stepLocation.filePath);
            const allFunctions = getAllFunctions(ast);

            /**
             * Function that contains the taint step.
             * @type {NodePath}
             */
            const enclosingFunction = allFunctions.findLast((path) =>
               containsPoint(
                  LocationRange.fromBabelNode(path.node),
                  stepLocation.startLine,
                  stepLocation.startColumn,
               ),
            );
            if (!enclosingFunction) {
               console.warn(`Unknown function at ${esc(stepLocation)}`);
               continue;
            }
            const prevFunctionSnippet =
               this.#cachedFunctionSnippets.length > 0
                  ? this.#cachedFunctionSnippets[this.#cachedFunctionSnippets.length - 1]
                  : null;

            if (
               prevFunctionSnippet &&
               prevFunctionSnippet.location.contains(stepLocation)
               /* &&
               (
                  // Ensure that the snippet belongs to the same function
                  prevFunctionSnippet.functionNodePath === enclosingFunction
                  // If the enclosing function is an anonymous function keep it.
                  || enclosingFunction.node.id === null
               )*/
            ) {
               // stepLocation belongs to previous snippet
               prevFunctionSnippet.stepLocations.push(stepLocation);
            } else {
               const newSnippet = new FunctionSnippet(
                  enclosingFunction,
                  [stepLocation],
               );
               this.#cachedFunctionSnippets.push(newSnippet);
            }
         }
      }
      return this.#cachedFunctionSnippets;
   }

   /**
    * @param {number} contextLines
    * @returns {string[]}
    */
   getSnippetsContext(contextLines = 0) {
      const steps = [];
      let prevLocKey = "";
      for (const location of this.taintStepLocations) {
         const prefix = `${location.filePath}:${location.startLine}`;
         if (prefix === prevLocKey) {
            continue;
         }
         const content = this.sarifFile.codeQL.getFileLine(
            location.filePath,
            location.startLine - 1,
            contextLines,
         );
         steps.push(`${prefix} ${content}\n`);
         prevLocKey = prefix;
      }
      return steps;
   }

   /**
    * Return the function coverage information for the given function snippet.
    *
    * @param {CoverageInfo[]} coverageInfoList
    * @param {FunctionSnippet} functionSnippet
    * @returns {null|CoverageFunction}
    */
   findFunctionCoverage(coverageInfoList, functionSnippet) {
      const relativePath = functionSnippet.stepLocations[0].filePath;
      const node = functionSnippet.functionNode;
      const coverageInfoFile = coverageInfoList.find(
         (e) => e.url === relativePath,
      );
      if (!coverageInfoFile) {
         return null;
      }
      // Find matching function
      return coverageInfoFile.functions.findLast((coverageFunction) =>
         coverageFunction.ranges.some((r) => r.startOffset === node.start),
      );
   }

   /**
    * This method iterates over all function snippets and checks if any of the taint steps
    * within the function snippet are not covered by the provided coverage information.
    *
    * @param {LocationRange[]} uncoveredLocations - List of coverage information objects.
    * @returns {StoppedFunction|undefined} - An instance of UncoveredFunctionSnippet if uncovered code is found that belongs to the taint path, otherwise undefined.
    */
   getStoppedFunction(uncoveredLocations) {
      const functionSnippets = this.functionSnippets;
      if (uncoveredLocations.length === 0) {
         // No locations means source was not executed.
         return new StoppedFunction(functionSnippets[0], 0, true);
      }
      for (let i = 0; i < functionSnippets.length; i++) {
         const functionSnippet = functionSnippets[i];
         // Check whether taint step exists that was not executed
         const uncoveredSteps = functionSnippet.stepLocations.filter((stepLocation) =>
            uncoveredLocations.some((uncovered) => uncovered.contains(stepLocation)),
         );
         if (uncoveredSteps.length > 0) {
            const entireFunctionNotExecuted = uncoveredLocations.some((uncovered) =>
               uncovered.contains(functionSnippet.location),
            );
            return new StoppedFunction(functionSnippet, i, entireFunctionNotExecuted);
         }
      }
      return undefined;
   }

   /**
    * @param {LocationRange[]} uncoveredLocations
    * @returns {LocationRange[]}
    */
   getUncoveredTaintSteps(uncoveredLocations) {
      return this.taintStepLocations.filter((step) =>
         uncoveredLocations.some((uncovered) =>
            uncovered.contains(step),
         ),
      );
   }

   /**
    * @param {LocationRange} location
    * @returns {boolean} true if the location is within the taint path
    */
   contains(location) {
      return this.functionSnippets.some((snippet) =>
         snippet.location.contains(location),
      );
   }

   /**
    * Concatenates another TaintPath to this one.
    * @param {TaintPath} other
    */
   concat(other) {
      if (!(other instanceof TaintPath)) {
         throw new TypeError("Argument must be an instance of TaintPath");
      }
      const tp = new TaintPath(this.sarifFile, this.source, null, this.llmSinks, [...this.taintStepLocations, ...other.taintStepLocations]);
      tp.vulnerabilityType = this.vulnerabilityType;
      return tp;
   }

   /**
    * Concatenates another TaintPath to this one.
    * @param {number} i
    */
   withFirstSteps(i) {
      const tp = new TaintPath(this.sarifFile, this.source, null, this.llmSinks, [...this.taintStepLocations.slice(0, i)]);
      tp.vulnerabilityType = this.vulnerabilityType;
      return tp;
   }

   toJSON() {
      const {sarifFile, ...rest} = this;
      rest.vulnerabilityTypeLabel = this.vulnerabilityType?.label;
      rest.functionSnippets = this.functionSnippets;
      return rest;
   }
}

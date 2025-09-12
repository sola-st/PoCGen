import LocationRange from "./locationRange.js";

/**
 * Wrapper class shared by refiners to store information about the refinement process.
 */
export default class RefinementInfo {

   /**
    * The runtime information used for refinement.
    *
    * @type {RuntimeInfo}
    */
   runtimeInfo;

   /**
    * Debug expressions that were evaluated.
    * @type {Array<{ functionSnippet: FunctionSnippet, breakPoints: HitBreakpoint[] }>}
    */
   sharedDebugExpressions = [];

   /**
    * The exploit that failed.
    *
    * @type {string}
    */
   failedExploit;

   /**
    * The original prompt to refine.
    *
    * @type {Prompt}
    */
   originalPrompt;

   /**
    * @type {PromptRefiner}
    */
   promptRefiner;

   /**
    * Constructs a new instance of RefinementInfo.
    *
    * @param {Object} params - The parameters for the constructor.
    * @param {PromptRefiner} params.promptRefiner - The prompt refiner instance.
    * @param {RuntimeInfo?} params.runtimeInfo - The runtime information.
    * @param {string?} params.failedExploit - The exploit that failed.
    * @param {Prompt?} params.originalPrompt - The original prompt to refine.
    */
   constructor({
                  promptRefiner,
                  runtimeInfo,
                  failedExploit,
                  originalPrompt
               }) {
      this.promptRefiner = promptRefiner;
      this.runtimeInfo = runtimeInfo;
      this.failedExploit = failedExploit;
      this.originalPrompt = originalPrompt;
   }

   /**
    * @returns {ErrorDetails[]}
    */
   get errorDetails() {
      return this.runtimeInfo?.errors.filter(e => e.stackFrames);
   }

   /**
    * @type {StoppedFunction|undefined}
    */
   get stoppedFunction() {
      if (this.uncoveredLocations === undefined)
         return undefined;
      return this.promptRefiner.taintPath.getStoppedFunction(this.uncoveredLocations);
   }

   /**
    * @returns {LocationRange[]|undefined}
    */
   get uncoveredTaintSteps() {
      return this.runtimeInfo?.coverageInfoList
         ? this.promptRefiner.taintPath.getUncoveredTaintSteps(this.uncoveredLocations)
         : undefined;
   }

   /**
    * @returns {LocationRange[]|undefined}
    */
   get uncoveredLocations() {
      return this.runtimeInfo?.coverageInfoList.flatMap(
         cvgInfo => cvgInfo.functions.flatMap(
            cvgFn => cvgFn.ranges.filter(s => s.count === 0)
               .map(range =>
                  LocationRange.fromStartEnd(
                     cvgInfo.url,
                     this.promptRefiner.taintPath.sarifFile.codeQL.readFile(cvgInfo.url),
                     range.startOffset,
                     range.endOffset,
                  ))
         )
      );
   }

   toJSON() {
      return {
         runtimeInfo: this.runtimeInfo,
         failedExploit: this.failedExploit,
         originalPrompt: this.originalPrompt,
      };
   }
}

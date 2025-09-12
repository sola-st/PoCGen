import DefaultRefiner from "./default.refiner.js";
import SummarizerOptions from "../summarizerOptions.js";
import {TaintPathSummarizer} from "../taintPathSummarizer.js";

export const description = "Replace taint path with function body but keep refiners.";

export default class C8Refiner extends DefaultRefiner {

   /** @inheritDoc */
   constructor(refinementInfo, refinementOptions) {
      super(refinementInfo, refinementOptions);
      this.refinementOptions.resolveReferences = false;
      this.refinementOptions.verbosity = SummarizerOptions.SnippetVerbosity.FULL_BODY;

      // Build new taint path that only consists of first snippet.
      this.taintPathFirstFunction = this.taintPath.withFirstSteps(1);
   }

   getTaintPathSnippets() {
      /**
       * @type {TaintPathSummarizerParams}
       */
      const taintPathOpts = {
         taintPath: this.taintPathFirstFunction,
         hitBreakPoints: this.hitBreakpoints,
      };

      if (this.refinementOptions.includeError) {
         taintPathOpts.options = new SummarizerOptions(true, this.refinementOptions.verbosity);
         taintPathOpts.errorDetails = this.refinementInfo.runtimeInfo?.errors.filter(e => e.stackFrames);
      } else {
         taintPathOpts.options = new SummarizerOptions(false, this.refinementOptions.verbosity);
      }

      taintPathOpts.options.taintComments = false;

      if (this.refinementOptions.includeCoverage) {
         taintPathOpts.stoppedSnippet = this.stoppedSnippet;
         taintPathOpts.uncoveredLocations = this.refinementInfo.uncoveredLocations;
      }

      return new TaintPathSummarizer(taintPathOpts).complete();
   }
}

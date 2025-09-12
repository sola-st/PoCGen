import DefaultRefiner from "./default.refiner.js";
import SummarizerOptions from "../summarizerOptions.js";

export const description = "Disable ContextRefiner.";

export default class C4Refiner extends DefaultRefiner {

   async refine() {
      if (this.refinementOptions.verbosity !== SummarizerOptions.SnippetVerbosity.CONTEXT) {
         return null;
      }
      return await super.refine();
   }

}

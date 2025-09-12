import DefaultRefiner from "./default.refiner.js";

export const description = "Disable reference exploits, apiReferences, apiCompletion.";

export default class C1Refiner extends DefaultRefiner {

   /** @inheritDoc */
   constructor(refinementInfo, refinementOptions) {
      super(refinementInfo, refinementOptions);
      this.refinementOptions.includeCWE = false;
      this.refinementOptions.includeSimilarExploits = false;
      this.refinementOptions.includeApiReferences = false;
      this.refinementOptions.includeApiCompletion = false;
   }

}

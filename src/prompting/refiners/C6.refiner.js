import DefaultRefiner from "./default.refiner.js";

export const description = "Disable reference exploits.";

export default class C6Refiner extends DefaultRefiner {

   /** @inheritDoc */
   constructor(refinementInfo, refinementOptions) {
      super(refinementInfo, refinementOptions);
      this.refinementOptions.includeSimilarExploits = false;
   }

}

import DefaultRefiner from "./default.refiner.js";

export const description = "Disable ErrorRefiner.";

export default class C2Refiner extends DefaultRefiner {

   /** @inheritDoc */
   constructor(refinementInfo, refinementOptions) {
      super(refinementInfo, refinementOptions);
      this.refinementOptions.includeError = false;
   }
}

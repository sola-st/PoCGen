import DefaultRefiner from "./default.refiner.js";

export const description = "Disable api references/ completion.";

export default class C7Refiner extends DefaultRefiner {

   /** @inheritDoc */
   constructor(refinementInfo, refinementOptions) {
      super(refinementInfo, refinementOptions);
      this.refinementOptions.includeApiReferences = false;
      this.refinementOptions.includeApiCompletion = false;
   }

}

import DefaultRefiner from "./default.refiner.js";

export const description = "Disable DebugRefiner.";

export default class C3Refiner extends DefaultRefiner {

   /** @inheritDoc */
   constructor(refinementInfo, refinementOptions) {
      super(refinementInfo, refinementOptions);
      this.refinementOptions.setBreakPoints = false;
   }
}

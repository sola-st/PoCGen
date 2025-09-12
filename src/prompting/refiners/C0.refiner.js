import DefaultRefiner from "./default.refiner.js";

export const description = "Replace taint path with function body.";

export default class C0Refiner extends DefaultRefiner {

   getTaintPathSnippets() {
      this.refinementOptions.resolveReferences = false;
      this.refinementOptions.setBreakPoints = false;

      // Only return function body.
      const snippet = this.taintPath.functionSnippets[0];
      return this.runner.codeQL.extractSourceCode(snippet.location);
   }
}

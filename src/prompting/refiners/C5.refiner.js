import DefaultRefiner from "./default.refiner.js";
import {renderPromptTemplate} from "../promptGenerator.js";
import {Prompt} from "../prompt.js";

export const description = "Single-prompt baseline that includes report and few-shot exploits.";

export default class C5Refiner extends DefaultRefiner {

   async refine() {
      this.renderVars = {
         vulnerabilityType: this.vulnerabilityType,
         vulnerabilityDescription: this.vulnerabilityDescription,
         package: this.package,
         source: this.source,
         similarExploits: this.promptRefiner.similarExploits
      }

      const sysPrompt = this.getSystemPrompt();
      const userPrompt = renderPromptTemplate(`exploitCreation/C5.user`, {
         ...this.renderVars,
      });
      return this.prompt = new Prompt(sysPrompt, userPrompt);
   }

}

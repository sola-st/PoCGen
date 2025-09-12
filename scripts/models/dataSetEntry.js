import {getCost} from "../runnerResultSummarizer.js";
import {LABELS} from "../constants.js";

export class DataSetEntry {
   /**
    * @type {Advisory}
    */
   advisory;

   /**
    * @type {string}
    */
   vulnerabilityTypeLabel;

   /**
    * @type {"y" | "fp" | ""}
    */
   label;

   /**
    * @type {RunnerResult|undefined}
    */
   runnerResult;

   /**
    * @type {{[p: string]: RunnerResult}}
    */
   runnerResultsAblation = {};

   /**
    * @param {Advisory} advisory
    * @param {string} vulnerabilityTypeLabel
    * @param {"y" | "fp" | ""} label
    */
   constructor(advisory, vulnerabilityTypeLabel, label) {
      this.advisory = advisory;
      this.vulnerabilityTypeLabel = vulnerabilityTypeLabel;
      this.label = label;
      if (!Object.values(LABELS).includes(label)) {
         throw new Error(`Invalid label: ${label}`);
      }
   }

   works() {
      return this.label === LABELS.TP;
   }

   falsePositive() {
      return this.label === LABELS.FP;
   }

   failure() {
      return this.label === LABELS.TN;
   }

   get cost() {
      return getCost(this.runnerResult);
   }

   get duration() {
      return this.getDurationFor("runner");
   }

   getDurationFor(name) {
      if (!this.runnerResult) {
         console.warn(`No runnerResult for ${this.advisory.id}`);
         return 0;
      }
      if (!this.runnerResult.performanceTracker[name]) {
         return 0;
      }
      return this.runnerResult.performanceTracker[name].reduce((acc, x) => acc + x.duration, 0);
   }

   get durationOnlyCodeQL() {
      if (!this.runnerResult) {
         console.warn(`No runnerResult for ${this.advisory.id}`);
         return 0;
      }
      // Get entries that starts with "CodeQL"
      const runs = this.runnerResult.performanceTracker;
      let d = 0;
      for (const [run, entry] of Object.entries(runs)) {
         if (run.startsWith("codeql")) {
            for (const e of entry) {
               d += e.duration;
            }
         }
      }
      return d;
   }

   get durationOnlyLLM() {
      if (!this.runnerResult) {
         console.warn(`No runnerResult for ${this.advisory.id}`);
         return 0;
      }
      // Get entries that starts with "LLM"
      const runs = this.runnerResult.performanceTracker;
      let d = 0;
      for (const [run, entry] of Object.entries(runs)) {
         if (run.startsWith("model")) {
            for (const e of entry) {
               d += e.duration;
            }
         }
      }
      return d;
   }

   get promptTokens() {
      if (!this.runnerResult.model) {
         console.warn(`No model for ${this.advisory.id}`);
         return 0;
      }
      return this.runnerResult.model.totalPromptTokens;
   }

   get completionTokens() {
      if (!this.runnerResult.model) {
         console.warn(`No model for ${this.advisory.id}`);
         return 0;
      }
      return this.runnerResult.model.totalCompletionTokens;
   }

   /**
    * @returns {Date}
    */
   get date() {
      return new Date(this.advisory.date);
   }

}

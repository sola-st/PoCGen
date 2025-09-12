import {isNumber} from "../../src/utils/utils.js";
import {LABELS, VULNERABILITY_LABELS, VULNERABILITY_LABELS_MAP} from "../constants.js";

export class DataSet {
   /**
    * @type {string}
    */
   name;

   constructor(name) {
      this.name = name;
   }

   /**
    * @type {DataSetEntry[]}
    */
   entries = [];

   get advisories() {
      return this.entries.map(e => e.advisory);
   }

   get costs() {
      return this.entries.map(e => e.cost).filter(s => isNumber(s) && !isNaN(s));
   }

   get durations() {
      return this.entries.map(e => e.duration).filter(s => isNumber(s) && !isNaN(s));
   }

   get promptTokens() {
      return this.entries.map(e => e.promptTokens).filter(s => isNumber(s) && !isNaN(s));
   }

   get completionTokens() {
      return this.entries.map(e => e.completionTokens).filter(s => isNumber(s) && !isNaN(s));
   }

   /**
    * @param lbl
    * @returns {Advisory[]}
    */
   byVulnerabilityTypeLabel(lbl) {
      return this.entriesByVulnerabilityTypeLabel(lbl).map(e => e.advisory);
   }

   /**
    * @param vulnerabilityTypeLabel
    * @param refinerName
    * @returns {RunnerResult[]}
    */
   byLabelAndRefiner(vulnerabilityTypeLabel, refinerName) {
      return this.entries.filter(e => e.vulnerabilityTypeLabel === vulnerabilityTypeLabel).map(s => s.runnerResultsAblation[refinerName]);
   }

   /**
    * @param lbl
    * @returns {DataSetEntry[]}
    */
   entriesByVulnerabilityTypeLabel(lbl) {
      return this.entries.filter(e => e.vulnerabilityTypeLabel === lbl);
   }

   ensureAllEntriesHaveYear() {
      for (const entry of this.entries) {
         if (isNaN(entry.advisory.year)) {
            throw new Error(`No year for ${entry.advisory.id}`);
         }
      }
   }

   /**
    * @returns {{[p: number]: DataSetEntry[]}}
    */
   groupByYear() {
      const groups = {};
      for (const entry of this.entries) {
         const year = entry.advisory.year;
         if (!groups[year]) {
            groups[year] = [];
         }
         groups[year].push(entry);
      }
      // Sort map based on year
      return Object.fromEntries(Object.entries(groups).sort((a, b) => a[0] - b[0]));
   }

   /**
    *
    * @returns {DataSetEntry[][]}
    */
   get duplicates() {
      const results = [];
      for (const entry of this.entries) {
         const dupes = this.entries.filter(e => (e.advisory.cve && e.advisory.cve === entry.advisory.cve) || e.advisory.id === entry.advisory.id);
         if (dupes.length > 1) {
            results.push(dupes);
         }
      }
      return results;
   }

   works(advisoryId) {
      for (const entry of this.entries) {
         if (entry.advisory.id === advisoryId && entry.label === LABELS.TP) {
            return true;
         }
      }
      return false;
   }

   falsePositive(advisoryId) {
      for (const entry of this.entries) {
         if (entry.advisory.id === advisoryId && entry.label === LABELS.FP) {
            return true;
         }
      }
      return false;
   }

   failure(advisoryId) {
      for (const entry of this.entries) {
         if (entry.advisory.id === advisoryId && entry.label === LABELS.TN) {
            return true;
         }
      }
      return false;
   }

   /**
    * @returns {DataSetEntry[]}
    */
   get working() {
      return this.entries.filter(e => e.label === LABELS.TP);
   }

   /**
    * @returns {DataSetEntry[]}
    */
   get falsePositives() {
      return this.entries.filter(e => e.label === LABELS.FP);
   }

   /**
    * @returns {DataSetEntry[]}
    */
   get failures() {
      return this.entries.filter(e => e.label === LABELS.TN);
   }

   get advisoryIds() {
      return this.entries.map(e => e.advisory.id);
   }

   dump(csv = false) {
      const map = {};
      for (const entry of this.entries) {
         const lbl = entry.vulnerabilityTypeLabel + " " + (entry.works() ? "TP" : (entry.falsePositive() ? "FP" : "TN"));
         map[lbl] = map[lbl] || 0;
         map[lbl]++;
      }
      if (csv) {
         const lines = [];
         console.log("Vulnerability,success,failure,falsePositive");
         for (const vLabel of VULNERABILITY_LABELS) {
            const success = this.entriesByVulnerabilityTypeLabel(vLabel).filter(e => e.works()).length;
            const failure = this.entriesByVulnerabilityTypeLabel(vLabel).filter(e => e.failure()).length;
            const falsePositive = this.entriesByVulnerabilityTypeLabel(vLabel).filter(e => e.falsePositive()).length;
            lines.push(`${VULNERABILITY_LABELS_MAP[vLabel]}, ${success}, ${failure}, ${falsePositive}`);
         }

         console.log(lines.join("\n"));
      } else {
         for (const key in map) {
            console.log(key, map[key]);
         }
         // success rate
         console.log(`Success rate: ${this.working.length} / ${this.entries.length} ${this.working.length / this.entries.length}`);
      }
   }

}

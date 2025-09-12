import {loadLabeledDataSet} from "./loadDataSetLabels.js";
import {loadRunnerResultsVulnIds} from "./loadRunnerResults.js";
import DefaultRefiner from "../src/prompting/refiners/default.refiner.js";
import {RESULTS_DIR, SEC_BENCH} from "./constants.js";
import {join} from "node:path";
import fs from "fs";
import {DataSet} from "./models/dataSet.js";
import {DataSetEntry} from "./models/dataSetEntry.js";
import Advisory from "../src/vulnerability-databases/advisory.js";
import {NpmPackage} from "../src/npm/npmPackage.js";
import {loadVulnerabilityTypes} from "../src/models/vulnerability.js";
import {fileURLToPath} from "node:url";

const vTypes = await loadVulnerabilityTypes();

export function loadExplodeJsDataSet() {
   const base = join(import.meta.dirname, "../explode-js");

   const file = join(base, "bench/explode-vulcan-secbench-results.csv")

   const ds = new DataSet("explode-js-secbench");

   const lines = fs.readFileSync(file, "utf-8").split("\n").slice(1);

   for (const line of lines) {
      const parts = line.split("|");
      if (parts.length < 11) {
         continue;
      }
      const works = parts[7] === "true"

      const advisory = new Advisory()
      advisory.package = NpmPackage.fromString(parts[0] + "@" + parts[1])

      const vulnLbl = vTypes.find(vtype => vtype.cwe.includes(parseInt(parts[3].split("-")[1]))).label;

      ds.entries.push(new DataSetEntry(
         advisory,
         vulnLbl,
         works ? "y" : "",
      ));
   }
   return ds;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {

   const secBenchDataSet = await loadLabeledDataSet(SEC_BENCH);
   secBenchDataSet.dump();

   for (const entry of loadRunnerResultsVulnIds(secBenchDataSet.advisoryIds, DefaultRefiner.name, join(RESULTS_DIR, SEC_BENCH))) {
      const dsEntry = secBenchDataSet.entries.find(e => e.advisory.id === entry.advisory.id);
      dsEntry.runnerResult = entry;
   }

   const explodeJsDataSet = loadExplodeJsDataSet();
   explodeJsDataSet.dump();

   let stats = {};

   for (let explodeJsEntry of explodeJsDataSet.entries) {
      const explodeJsAdv = explodeJsEntry.advisory;

      let genpoc = secBenchDataSet.entries.filter(
         s => s.advisory.package.name === explodeJsAdv.package.name &&
            s.advisory.package.version === explodeJsAdv.package.version
      )
      if (genpoc.length === 0) {
         console.warn(`No secbench.js entry for ${explodeJsAdv.package.name}@${explodeJsAdv.package.version}`);
         continue;
      }
      if (genpoc.length > 1) {
         console.warn(`Multiple matches for ${explodeJsAdv.package.name}@${explodeJsAdv.package.version}`);
      }
      genpoc = genpoc[0];
      if (genpoc.vulnerabilityTypeLabel !== explodeJsEntry.vulnerabilityTypeLabel) {
         console.warn(`Vulnerability type mismatch for ${explodeJsAdv.package.name}@${explodeJsAdv.package.version}: ${genpoc.vulnerabilityTypeLabel} != ${explodeJsEntry.vulnerabilityTypeLabel}`);
      }
      const lbl = genpoc.vulnerabilityTypeLabel + ": " + (genpoc.works() ? "genpoc works" : "genpoc does not work") + " -- " + (explodeJsEntry.works() ? "exp.js works" : "exp.js does not work");
      stats[lbl] = stats[lbl] || [];
      stats[lbl].push(genpoc.advisory.id);

      if (!genpoc.works() && explodeJsEntry.works()) {
         console.warn(`Explode.js works for ${genpoc.advisory.id}:  ${explodeJsAdv.package.name}@${explodeJsAdv.package.version} but secbench.js does not!`);
      }
   }

   for (const lbl in stats) {
      console.log(stats[lbl].length, lbl);
   }

}

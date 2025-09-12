import {join} from "node:path";
import DefaultRefiner from "../src/prompting/refiners/default.refiner.js";
import {doesWork} from "./runnerResultSummarizer.js";
import fs from "fs";
import {DATASET_DIR, RESULTS_DIR, SEC_BENCH} from "./constants.js";
import {loadLabeledDataSet} from "./loadDataSetLabels.js";
import {loadRunnerResultsVulnIds} from "./loadRunnerResults.js";

async function gen(dataSetName, runnerResultsLocation, refinerName = DefaultRefiner.name) {
   const dataSet = await loadLabeledDataSet(dataSetName);
   const loadedRunnerResults = loadRunnerResultsVulnIds(dataSet.advisoryIds, refinerName, join(RESULTS_DIR, runnerResultsLocation));

   /**
    * @type {DataSetEntry[]}
    */
   const missingWorking = [];

   /**
    * @type {DataSetEntry[]}
    */
   const failedButAdded = [];

   for (const entry of dataSet.entries) {
      const runnerResult = loadedRunnerResults.find(e => e.advisory.id === entry.advisory.id);
      if (!runnerResult) {
         console.error("No runner result for: " + entry.advisory.id);
         continue;
      }
      if (entry.works() && !doesWork(runnerResult)) {
         failedButAdded.push(entry);
      }
      if ((!entry.works() && !entry.falsePositive()) && doesWork(runnerResult)) {
         missingWorking.push(entry);
      }
   }
   console.warn(`Failed but added: ${failedButAdded.length}`);
   for (const e of failedButAdded) {
      console.log(e.advisory.id);
   }

   // get missing
   const notExecuted = [];
   for (const entry of dataSet.entries) {
      if (!loadedRunnerResults.find(e => e.advisory.id === entry.advisory.id)) {
         notExecuted.push(entry.advisory.id);
      }
   }
   for (const e of notExecuted) {
      console.error("notExecuted: ", e)
   }

   fs.writeFileSync(join(DATASET_DIR, dataSetName, "missing"), notExecuted.join("\n"))

   console.warn(`Missing working: ${missingWorking.length}`);
   for (const entry of missingWorking) {
      const runnerResult = loadedRunnerResults.find(e => e.advisory.id === entry.advisory.id);
      console.log(entry.advisory.id + " -- " + runnerResult.exploitSuccessResult.workingTaintPath?.vulnerabilityType?.label);
      console.log(runnerResult.exploitSuccessResult.workingExploit)
      console.log("__".repeat(100))
   }
}

await gen(SEC_BENCH, SEC_BENCH, DefaultRefiner.name);
// await gen(CWE_BENCH, CWE_BENCH);

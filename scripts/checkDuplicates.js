import {DATASET_NAMES} from "./constants.js";
import {loadLabeledDataSet} from "./loadDataSetLabels.js";
import {fileURLToPath} from "node:url";
import {DataSet} from "./models/dataSet.js";

function printDupes(dsName, dataSet) {
   for (const dupes of dataSet.duplicates) {
      console.log(`Duplicate ${dsName}`);
      for (const dupe of dupes) {
         console.log(" -- " + dsName + " --- " + dupe.vulnerabilityTypeLabel + " --- " + dupe.advisory.id + " " + dupe.advisory.cve);
      }
   }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
   const dataSets = []
   for (const dsName of DATASET_NAMES) {
      const dataSet = await loadLabeledDataSet(dsName);
      dataSets.push(dataSet);
      printDupes(dsName, dataSet);
   }
   // Cross-check
   const dataSet = new DataSet();
   dataSet.entries = dataSets.flatMap(ds => ds.entries);
   printDupes("all", dataSet);

}

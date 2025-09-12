import {join} from "path";
import {LABELS_DIR, SEC_BENCH} from "./constants.js";
import fs from "node:fs";
import {DataSet} from "./models/dataSet.js";
import {DataSetEntry} from "./models/dataSetEntry.js";
import {loadLabeledDataSet} from "./loadDataSetLabels.js";

const secBenchDS = await loadLabeledDataSet(SEC_BENCH)

const mdFile = join(LABELS_DIR, "agent", "results.md");
const lines = fs.readFileSync(mdFile, 'utf8').split('\n').splice(2);

const ds = new DataSet("secbench.agent");
for (const line of lines) {
   if (line.trim().length === 0 || !line.startsWith('|')) {
      continue;
   }
   const advId = line.split('|')[1].trim();
   const label = line.split('|')[3].trim();

   const adv = secBenchDS.entries.find(e => e.advisory.id === advId);
   const entry = new DataSetEntry(adv.advisory, adv.vulnerabilityTypeLabel, label);
   ds.entries.push(entry)
}

console.log(`Loaded ${ds.entries.length} entries from ${mdFile}`);

ds.dump(true);

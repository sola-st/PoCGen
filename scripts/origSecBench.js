import {SEC_BENCH, VULNERABILITY_LABELS} from "./constants.js";
import fs from "node:fs";
import {join} from "node:path";
import {loadExplodeJsDataSet} from "./explodeJsDataSet.js";
import {loadLabeledDataSet} from "./loadDataSetLabels.js";

export function loadSecBenchLocal(dir) {
   const subFolders = ["incubator", ...VULNERABILITY_LABELS];
   const data = {};
   for (const label of subFolders) {
      data[label] = [];

      const dirs = fs.readdirSync(`${dir}/${label}`);

      for (const d of dirs) {
         try {
            const file = `${dir}/${label}/${d}`;
            if (fs.statSync(file).isDirectory()) {
               const packageFile = `${file}/package.json`;
               const obj = JSON.parse(fs.readFileSync(packageFile, "utf-8"));
               const parts = d.split("_");
               const pkg = parts[0];
               const version = parts[1];
               obj.package = pkg;
               obj.version = version;
               obj.label = label;

               data[label].push(obj);
            }
         } catch (e) {
         }
      }
   }
   return data;
}

let d = loadSecBenchLocal(join(import.meta.dirname, "../../SecBench.js"));

// amount sinks
const origSecBench = Object.values(d).flat();
const withSink = origSecBench.filter(s => s.sink);
console.log("with sinks", withSink.length);

const explodeJsDataSet = loadExplodeJsDataSet();

const genpocSecBench = await loadLabeledDataSet(SEC_BENCH);

const missing = []
for (const ds of explodeJsDataSet.entries) {
   // Find entries not in our evaluation
   let genpocMatch = genpocSecBench.entries.filter(s =>
      s.advisory.package.name === ds.advisory.package.name
      && s.advisory.package.version === ds.advisory.package.version
   );
   if (genpocMatch.length === 0) {
      genpocMatch = genpocSecBench.entries.filter(s =>
         s.advisory.package.name === ds.advisory.package.name
      );
   }

   if (genpocMatch.length === 0) {
      // print when label !== "incubator"
      let matchOrigSecbench = origSecBench.find(s =>
         s.package === ds.advisory.package.name
         && s.version === ds.advisory.package.version
      );
      if (!matchOrigSecbench) {
         matchOrigSecbench = origSecBench.find(s =>
            s.package === ds.advisory.package.name
         );
      }

      if (!matchOrigSecbench) {
         console.warn("not found", ds.advisory.package.name, ds.advisory.package.version);
      } else if (matchOrigSecbench.label !== "incubator") {
         console.log("missing in genpoc", ds.advisory.package.name, ds.advisory.package.version, matchOrigSecbench.label);
         missing.push(ds.advisory.package.name + "@" + ds.advisory.package.version);
      }
   } else if (genpocMatch.length !== 1) {
      console.warn("found", genpocMatch.length, ":", ds.advisory.package.name, ds.advisory.package.version);
   }
}

console.dir(missing)

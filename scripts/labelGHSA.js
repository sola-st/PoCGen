import {join} from "node:path";
import fs from "fs";
import {CWE_BENCH, DATASET_DIR, SEC_BENCH} from "./constants.js";
import {loadLabeledDataSet} from "./loadDataSetLabels.js";

const secbenchAdvisoriesMap = await loadLabeledDataSet(SEC_BENCH);

const cweBenchAdvisoryIds = await loadLabeledDataSet(CWE_BENCH);

/**
 * @type {Advisory[]}
 */
const secbenchAdvisories = Object.values(secbenchAdvisoriesMap).flat();

const outJson = join(DATASET_DIR, "GHSA.json");

const results = JSON.parse(fs.readFileSync(outJson, 'utf8'));

let pat = ["redos", "inefficient regular expression"]
let filterCwes = [1333]
let vtype;

pat = ["shell injection", "command injection", "os injection",
   "shell-injection", "command-injection", "os-injection"
]
filterCwes = [77, 78]

vtype = "prototype-pollution"
pat = ["prototype pollution", "prototype-pollution"]
// pat = ["pollution"]
filterCwes = [1321]

/*
pat = ["code injection"]
filterCwes = [94, 95, 96, 97, 98, 99]
*/

const addedPatNew = []

const newVulns = results.filter(res => {
   const ghsaId = res.ghsa_id;
   const cveId = res.cve_id;
   // remove ones contained in secbench
   let added = secbenchAdvisories.find(s => s.id === ghsaId || s.cve && s.cve === cveId);
   if (added) {
      return false;
   }
   added = cweBenchAdvisoryIds[vtype].find(s => s.id === ghsaId || s.cve && s.cve === cveId);
   if (added) {
      return false;
   }

   const cwes = res.cwes.map(c => c.cwe_id.split("-")[1]).map(Number);
   if (cwes.some(c => filterCwes.includes(c))) {
      return true;
   }
   if (pat.some(el => res.summary.toLowerCase().includes(el) || res.description.toLowerCase().includes(el))) {
      addedPatNew.push(res)
      return true;
   }
   return false;
});

for (const e of newVulns) {
   console.log(`| ${e.ghsa_id} | ${e.cve_id ? e.cve_id + ": " : ""}${e.summary} |  |`);
}
console.log(newVulns.length)

console.log(`pattern matches: ${addedPatNew.length}`)
for (const e of addedPatNew) {
   console.log(`| ${e.ghsa_id} | ${e.cve_id ? e.cve_id + ": " : ""}${e.summary} |  |`);
}

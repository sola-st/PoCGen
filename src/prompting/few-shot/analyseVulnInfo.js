import * as fs from "node:fs";

const vulnInfo = JSON.parse(fs.readFileSync("./vulnInfo.json", "utf-8"));

let entriesAmount = 0;

let snykTotal = 0;
let snykCorrectSourceName = 0;
let snykHasSource = 0;
let snykCorrectVType = 0;
let synkIncorrectVTypes = [];

let ghsaTotal = 0;
let ghsaCorrectSourceName = 0;
let ghsaHasSource = 0;

let ghsaCorrectVType = 0;
let ghsaIncorrectVTypes = [];

for (const vType of vulnInfo) {
   for (const exploitEntry of vType.entries) {
      try {
         entriesAmount++;
         const {dbInfo, exploitSourceName} = exploitEntry;
         const {snyk, ghsa} = dbInfo.llmDerived;
         if (snyk) {
            snykTotal++;
            if (
               snyk.llmIdentifiedVulnerabilityTypes?.includes(vType.vulnerabilityType)
            ) {
               snykCorrectVType++;
            } else {
               synkIncorrectVTypes.push({
                  expected: vType.vulnerabilityType,
                  llm: snyk.llmIdentifiedVulnerabilityTypes,
                  description: snyk.description,
               });
            }
            if (snyk.sourceName.toLowerCase() === "none") {
               snykHasSource++;
            } else if (
               snyk.sourceName.toLowerCase() === exploitSourceName.toLowerCase()
            ) {
               snykCorrectSourceName++;
            } else {
               console.warn(
                  `Snyk source name: ${snyk.sourceName} | Exploit source name: ${exploitSourceName}`,
               );
            }
         }
         if (ghsa) {
            ghsaTotal++;
            if (
               ghsa.llmIdentifiedVulnerabilityTypes?.includes(vType.vulnerabilityType)
            ) {
               ghsaCorrectVType++;
            } else {
               ghsaIncorrectVTypes.push({
                  expected: vType.vulnerabilityType,
                  llm: ghsa.llmIdentifiedVulnerabilityTypes,
                  description: ghsa.redactedDescription,
               });
            }
            if (ghsa.sourceName.toLowerCase() === "none") {
               ghsaHasSource++;
            } else if (
               ghsa.sourceName.toLowerCase() === exploitSourceName.toLowerCase()
            ) {
               ghsaCorrectSourceName++;
            } else {
               console.warn(
                  `Ghsa source name: ${ghsa.sourceName} | Exploit source name: ${exploitSourceName} | description: ${JSON.stringify(ghsa.redactedDescription)}`,
               );
            }
         }
      } catch (e) {
         console.error(exploitEntry, e);
      }
   }
}

console.log(`Total: ${entriesAmount}`);
console.log(`Ghsa correct source: ${ghsaCorrectSourceName} / ${ghsaTotal}`);
console.log(`Snyk correct source: ${snykCorrectSourceName} / ${snykTotal}`);
console.log(`Ghsa has no source: ${ghsaHasSource} / ${ghsaTotal}`);
console.log(`Snyk has no source: ${snykHasSource} / ${snykTotal}`);
console.log(`Ghsa correct vType: ${ghsaCorrectVType} / ${ghsaTotal}`);
console.log(`Snyk correct vType: ${snykCorrectVType} / ${snykTotal}`);

console.log("Ghsa incorrect vTypes: ", ghsaIncorrectVTypes.length);
console.log("Snyk incorrect vTypes: ", synkIncorrectVTypes.length);

for (const vType of synkIncorrectVTypes) {
   console.log(vType);
}

/*for (const vType of ghsaIncorrectVTypes) {
   console.log(vType);
}*/

// group based on vulnerability type

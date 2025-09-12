import fs from "node:fs";
import {fromJson} from "./runnerResultSummarizer.js";
import {join} from "node:path";
import DefaultRefiner from "../src/prompting/refiners/default.refiner.js";
import {isDefaultRefinerName} from "./constants.js";

const homeDir = process.env.HOME;
export const OUTPUT_DIR = join(homeDir, "gen-poc", "output");

const cache = {};

/**
 * @param advisoryId
 * @param refiner
 * @param runnerResultBaseDir
 * @returns {RunnerResult|null}
 */
function loadRunnerResult(advisoryId, refiner = DefaultRefiner.name, runnerResultBaseDir = OUTPUT_DIR) {
   if (cache[advisoryId + refiner + runnerResultBaseDir]) {
      return cache[advisoryId + refiner + runnerResultBaseDir];
   }
   const dirname = advisoryId.replace(/[^a-zA-Z0-9\-]/g, "_");
   let path;
   if (!refiner || isDefaultRefinerName(refiner)) {
      path = `${runnerResultBaseDir}/${dirname}/RunnerResult.json`;
      if (!fs.existsSync(path)) {
         path = `${runnerResultBaseDir}/${dirname}/RunnerResult_${DefaultRefiner.name}.json`;
      }
   } else {
      path = `${runnerResultBaseDir}/${dirname}/RunnerResult_${refiner}.json`;
   }
   if (fs.existsSync(path)) {
      const data = JSON.parse(fs.readFileSync(path, "utf-8"));
      const runnerResult = fromJson(data);
      if (!runnerResult.advisory?.id) {
         console.error(`No advisory id: ${path}`);
      } else {
         return runnerResult;
      }
   } else {
      console.error(`File not found: ${path}`);
   }
   return null;
}

/**
 * @param filePathWithVulnIds
 * @param refiner
 * @param runnerResultBaseDir
 * @returns {RunnerResult[]}
 */
export default function loadRunnerResults(filePathWithVulnIds, refiner = DefaultRefiner.name, runnerResultBaseDir = OUTPUT_DIR) {
   if (cache[filePathWithVulnIds + refiner]) {
      return cache[filePathWithVulnIds + refiner];
   }
   const vulnIds = fs.readFileSync(filePathWithVulnIds, "utf-8").split("\n").filter(x => !x.startsWith("#"));
   return cache[filePathWithVulnIds + refiner] = loadRunnerResultsVulnIds(vulnIds, refiner, runnerResultBaseDir);
}

/**
 * @param vulnIds
 * @param refiner
 * @param runnerResultBaseDir
 * @returns {RunnerResult[]}
 */
export function loadRunnerResultsVulnIds(vulnIds, refiner = DefaultRefiner.name, runnerResultBaseDir = OUTPUT_DIR) {
   const runnerResults = []
   const missing = [];
   for (const vulnId of vulnIds) {
      if (vulnId.trim().length === 0) {
         continue;
      }
      const runnerResult = loadRunnerResult(vulnId, refiner, runnerResultBaseDir);
      if (runnerResult) {
         runnerResults.push(runnerResult);
      } else {
         missing.push(vulnId);
      }
   }
   if (missing.length > 0) {
      console.log(`Missing ${missing.length} runner results for ${refiner}: ${missing.join(" ")}`);
   }
   return runnerResults;
}

import {DATASET_DIR, DEFAULT, isDefaultRefinerName, LABELS_DIR, SEC_BENCH, VULNERABILITY_LABELS} from "./constants.js";
import fs from "fs";
import GhsaApi, {isValidGhsaId} from "../src/vulnerability-databases/ghsaApi.js";
import SnykApi, {isValidSnykId} from "../src/vulnerability-databases/snykApi.js";
import {esc, loadEnv, rmSuffix} from "../src/utils/utils.js";
import {join} from "node:path";
import path from "path";
import {DataSetEntry} from "./models/dataSetEntry.js";
import {DataSet} from "./models/dataSet.js";
import {fileURLToPath} from "node:url";

loadEnv();

const ghsaApi = new GhsaApi();
const snykApi = new SnykApi();

const cache = {};

/**
 * @param {string} dataSetName
 * @returns {Promise<Advisory[]>}
 */
async function loadAdvisoriesFromJson(dataSetName) {
   if (cache["loadAdvisoriesFromJson." + dataSetName]) {
      return cache["loadAdvisoriesFromJson." + dataSetName];
   }
   /**
    * @type {Advisory[]}
    */
   const loadedAdvisories = [];
   for (const vulnerabilityTypeLabel of VULNERABILITY_LABELS) {
      const jsonFilePath = path.join(DATASET_DIR, dataSetName, vulnerabilityTypeLabel + ".json");
      if (fs.existsSync(jsonFilePath)) {
         loadedAdvisories.push(...JSON.parse(fs.readFileSync(jsonFilePath, 'utf8')));
      }
   }
   return cache["loadAdvisoriesFromJson." + dataSetName] = loadedAdvisories;
}

/**
 * @param {string} dataSetName
 * @param {string} vulnerabilityTypeLabel
 * @returns {Promise<{advisoryId: string, error: *}[]|*>}
 */
async function loadErrorsJson(dataSetName, vulnerabilityTypeLabel) {
   if (cache["loadErrorsJson." + dataSetName + "." + vulnerabilityTypeLabel]) {
      return cache["loadErrorsJson." + dataSetName + "." + vulnerabilityTypeLabel];
   }
   const errorPath = path.join(DATASET_DIR, dataSetName, vulnerabilityTypeLabel + ".errors.json");

   /**
    * @type {{advisoryId: string, error: any}[]}
    */
   let errors = [];
   if (fs.existsSync(errorPath)) {
      errors.push(...JSON.parse(fs.readFileSync(errorPath, 'utf8')));
   }
   return cache["loadErrorsJson." + dataSetName + "." + vulnerabilityTypeLabel] = errors;
}

/**
 * @param {string} advisoryId
 * @param {string} dataSetName
 * @returns {Promise<Advisory>}
 */
async function loadAdvisory(advisoryId, dataSetName) {
   const advisories = await loadAdvisoriesFromJson(dataSetName);
   return advisories.find(a => a.id === advisoryId);
}

/**
 * @param {string} dataSetName
 * @param {string} vulnerabilityTypeLabel
 * @param {DataSet} dataSet
 */
export async function updateLocalFiles(dataSetName, vulnerabilityTypeLabel, dataSet) {
   const dataSetDir = path.join(DATASET_DIR, dataSetName);

   const advisoryIds = dataSet.advisoryIds;

   // Split ids into chunks of 30 and add it to files <name>.<index>
   const chunkSize = 30;
   for (let i = 0; i < advisoryIds.length; i += chunkSize) {
      const chunk = advisoryIds.slice(i, i + chunkSize);
      fs.mkdirSync(path.join(dataSetDir, "chunks"), {recursive: true});
      const chunkPath = path.join(dataSetDir, "chunks", `${vulnerabilityTypeLabel}.${i / chunkSize}`);
      fs.writeFileSync(chunkPath, chunk.join('\n'));
   }
   fs.writeFileSync(path.join(dataSetDir, vulnerabilityTypeLabel), advisoryIds.join('\n'));

   fs.writeFileSync(path.join(dataSetDir, vulnerabilityTypeLabel + ".json"), JSON.stringify(dataSet.advisories, null, 3));

   const failures = dataSet.failures;
   const working = dataSet.working;
   const falsePositives = dataSet.falsePositives;

   const nonWorkingPath = join(DATASET_DIR, dataSetName, `nonworking`);

   for (let i = 0; i < failures.length; i += chunkSize) {
      const chunk = failures.slice(i, i + chunkSize).map(s => s.advisory.id);
      fs.mkdirSync(nonWorkingPath, {recursive: true});
      const chunkPath = path.join(nonWorkingPath, `${vulnerabilityTypeLabel}.${i / chunkSize}`);
      fs.writeFileSync(chunkPath, chunk.join('\n'));
   }

   const workingPath = join(DATASET_DIR, dataSetName, `${vulnerabilityTypeLabel}.working`);
   fs.writeFileSync(workingPath, working.map(s => s.advisory.id).join('\n'));

   const failPath = join(DATASET_DIR, dataSetName, `${vulnerabilityTypeLabel}.failures`);
   fs.writeFileSync(failPath, failures.map(s => s.advisory.id).join('\n'));

   const falsePositivesPath = join(DATASET_DIR, dataSetName, `${vulnerabilityTypeLabel}.falsePositives`);
   fs.writeFileSync(falsePositivesPath, falsePositives.map(s => s.advisory.id).join('\n'));

   const allPath = join(DATASET_DIR, dataSetName, `${vulnerabilityTypeLabel}.all`);
   fs.writeFileSync(allPath, dataSet.advisoryIds.join('\n'));
}

/**
 * @param {string} dataSetName
 * @param {string} [refinerName]
 * @returns {Promise<DataSet>}
 */
export async function loadLabeledDataSet(dataSetName, refinerName = DEFAULT) {
   if (cache["loadLabeledDataSet." + dataSetName + "." + refinerName]) {
      return cache["loadLabeledDataSet." + dataSetName + "." + refinerName];
   }
   const result = new DataSet(dataSetName);
   for (const vulnerabilityTypeLabel of VULNERABILITY_LABELS) {
      const dataSet = await loadLabeledDataSetForVulnerability(dataSetName, refinerName, vulnerabilityTypeLabel);
      result.entries.push(...dataSet.entries);
      console.log(`loadLabeledDataSet: ${dataSetName}/${vulnerabilityTypeLabel}/${refinerName}: ${dataSet.entries.length}`)
      await updateLocalFiles(dataSetName, vulnerabilityTypeLabel, dataSet);
   }

   if (isDefaultRefinerName(refinerName)) {
      fs.writeFileSync(join(DATASET_DIR, dataSetName + ".all"), result.advisoryIds.join('\n'));
      // .working
      fs.writeFileSync(join(DATASET_DIR, dataSetName + ".working"), result.working.map(s => s.advisory.id).join('\n'));
   }
   return cache["loadLabeledDataSet." + dataSetName + "." + refinerName] = result;
}

/**
 * @param {string} dataSetName
 * @param {string} vulnerabilityTypeLabel
 * @param {string} refinerName
 * @returns {Promise<DataSet>}
 */
async function loadLabeledDataSetForVulnerability(dataSetName, refinerName, vulnerabilityTypeLabel) {
   const mdFile = `${LABELS_DIR}/${dataSetName}/${isDefaultRefinerName(refinerName) ? "" : refinerName + "/"}${vulnerabilityTypeLabel.toUpperCase()}.md`;
   return await loadLabeledDataSetFromFile(mdFile, dataSetName, refinerName, vulnerabilityTypeLabel);
}

export async function loadLabeledDataSetFromFile(mdFile, dataSetName, refinerName, vulnerabilityTypeLabel) {
   const advisories = await loadAdvisoriesFromJson(dataSetName);
   const dataSet = new DataSet(dataSetName);
   const md = fs.readFileSync(mdFile, 'utf8').split('\n');
   const tableEntry = md.filter(line => line.startsWith('|'));
   for (const row of tableEntry) {
      if (row.startsWith("| vulnId") || row.startsWith("| ---")) {
         continue;
      }
      const cleaned = rmSuffix(row.replace(/\s+/g, ''), '|');
      const spl = cleaned.split('|');
      const advisoryId = spl[1];
      if (!isValidGhsaId(advisoryId) && !isValidSnykId(advisoryId)) {
         throw new Error(`Invalid advisoryId: ${mdFile} - ${esc(row)}`);
      }
      const label = spl.pop();

      let advisory = advisories.find(a => a.id === advisoryId);
      if (!advisory && !isDefaultRefinerName(refinerName)) {
         continue;
      }

      if (!advisory) {
         const loadedErrors = await loadErrorsJson(dataSetName, vulnerabilityTypeLabel);
         if (loadedErrors.find(e => e.advisoryId === advisoryId)) {
            console.log(`Skipping advisory: ${advisoryId} due to previous error`);
            continue;
         }
         console.log(`Fetching advisory: ${advisoryId}`);
         try {
            if (isValidGhsaId(advisoryId)) {
               advisory = await ghsaApi.getAdvisory(advisoryId);
            } else {
               advisory = await snykApi.getAdvisory(advisoryId);
            }
         } catch (e) {
            console.error(`Error fetching advisory: ${advisoryId}: ${e}`);
            loadedErrors.push({advisoryId, error});
            // Sync to file
            const errorPath = path.join(DATASET_DIR, dataSetName, vulnerabilityTypeLabel + ".errors.json");
            fs.writeFileSync(errorPath, JSON.stringify(loadedErrors, null, 3));
         }
      }
      try {
         dataSet.entries.push(new DataSetEntry(advisory, vulnerabilityTypeLabel, label));
      } catch (e) {
         throw new Error(`Error creating DataSetEntry: ${dataSetName}/${refinerName}/${vulnerabilityTypeLabel}: ${advisoryId}: ${e}`);
      }
   }
   return dataSet;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
   (await loadLabeledDataSet(SEC_BENCH)).dump(true)
}

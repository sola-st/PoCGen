import * as fs from "node:fs";
import {TaintPath} from "./taintPath.js";
import LocationRange from "../../models/locationRange.js";

export const MAX_PATH_SAME_SOURCE_SINK = 5;

/**
 * @typedef {import("../../models/source").default} Source
 */

/**
 * Remove a codeFlow if the source+sink pair already occurs {@link MAX_PATH_SAME_SOURCE_SINK} times
 * @param {any[]} codeFlows
 * @returns {object[]}
 */
function deduplicateCodeFlows(codeFlows) {
   const filteredCodeFlows = [];
   const seen = new Map();
   for (const codeFlow of codeFlows) {
      const locations = codeFlow.threadFlows[0].locations;
      const key =
         JSON.stringify(
            LocationRange.fromCodeQL(locations[0].location.physicalLocation),
         ) +
         JSON.stringify(
            LocationRange.fromCodeQL(
               locations[locations.length - 1].location.physicalLocation,
            ),
         );
      if (seen.has(key)) {
         seen.set(key, seen.get(key) + 1);
      } else {
         seen.set(key, 1);
      }
      if (seen.get(key) <= MAX_PATH_SAME_SOURCE_SINK) {
         filteredCodeFlows.push(codeFlow);
      } else {
         console.log(
            `Ignoring codeFlow starting at ${JSON.stringify(locations[0].location.physicalLocation)} as it occurs more than ${MAX_PATH_SAME_SOURCE_SINK} times`,
         );
      }
   }
   return filteredCodeFlows;
}

/**
 * Get taint paths in order based on the provided sources.
 *
 * @param {Source[]} sources - The list of sources to match against taint paths.
 * @param {TaintPath[]} taintPaths - The list of taint paths to be ordered.
 * @returns {TaintPath[]} - The ordered list of taint paths.
 */
export function getTaintPathsInOrder(sources, taintPaths) {
   const result = [];
   for (const source of sources) {
      for (const taintPath of taintPaths) {
         if (taintPath.source === source) {
            result.push(taintPath);
         }
      }
   }
   // Add all tainted sources that are not in the sources list
   for (const taintPath of taintPaths) {
      if (!sources.includes(taintPath.source)) {
         result.push(taintPath);
      }
   }
   return result;
}

/**
 * Parse a SARIF file as JSON.
 * @param sarifFilePath
 * @returns {any}
 */
export function parseSarifAsJson(sarifFilePath) {
   return JSON.parse(fs.readFileSync(sarifFilePath, "utf8"));
}

export default class SarifFile {

   /**
    * @param {CodeQLDatabase} codeQL
    * @param {Source[]} sources
    * @param {string} sarifFilePath
    * @param {PotentialSink[]} llmSinks
    * @returns {SarifFile}
    */
   static parseSarif(codeQL, sources, sarifFilePath, llmSinks) {
      const sarif = parseSarifAsJson(sarifFilePath);

      let codeFlows = [];
      for (const result of sarif.runs[0].results) {
         if (result.codeFlows) {
            codeFlows.push(...result.codeFlows);
         } else if (result.locations) {
            const codeFlow = {};
            codeFlow.threadFlows = [
               {
                  locations: result.locations.map((ph) => {
                     return {location: ph};
                  }),
               },
            ];
            codeFlows.push(codeFlow);
         }
      }

      const sarifFile = new SarifFile(codeQL, []);

      codeFlows = deduplicateCodeFlows(codeFlows);
      for (const codeFlow of codeFlows) {
         const taintPath = new TaintPath(sarifFile, null, codeFlow, llmSinks);
         const firstStepLocation = taintPath.taintStepLocations[0];
         const matchingSource = sources.find((source) =>
            LocationRange.contains(source.callable.location, firstStepLocation),
         );
         if (matchingSource) {
            taintPath.source = matchingSource;
         } else {
            console.warn(
               `Could not map taint path ${firstStepLocation.toString()} to any source`,
            );
         }
         sarifFile.taintPaths.push(taintPath);
      }
      return sarifFile;
   }

   /**
    * @type {TaintPath[]}
    */
   taintPaths = [];

   /**
    * @param {CodeQLDatabase} codeQL
    * @param {TaintPath[]} [taintPaths]
    */
   constructor(codeQL, taintPaths = []) {
      this.codeQL = codeQL;
      this.taintPaths = taintPaths;
   }

   /**
    * @param {Source[]} sources
    * @returns {TaintPath[]}
    */
   getTaintPathsInOrder(sources) {
      return getTaintPathsInOrder(sources, this.taintPaths);
   }
}

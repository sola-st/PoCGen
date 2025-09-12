import {ciEquals} from "../utils/utils.js";

/**
 * @typedef {import("../analysis/api-explorer/apiExplorerResult.js").default} ApiExplorerResult
 * @class
 */
export default class ApiExplorerList {

   /**
    * @type {ApiExplorerResult[]}
    */
   list = [];

   moduleName;

   push(apiExplorerResult) {
      this.list.push(apiExplorerResult);
   }

   /**
    * @returns {string[]}
    */
   get errors() {
      return this.list.flatMap((s) => s.errors);
   }

   /**
    * @returns {Source[]}
    */
   get sources() {
      return Object.values(this.list).flatMap((s) => s.getSources());
   }

   get sourcesInScope() {
      return this.sources.filter((s) => s.callable.location.filePath.startsWith(this.moduleName));
   }

   get sourcesOutOfScope() {
      return this.sources.filter((s) => !s.callable.location.filePath.startsWith(this.moduleName));
   }

   /**
    * Filters and returns candidate sources based on the identified function name.
    *
    * @param {string} llmIdentifiedFunctionName - The function name identified by the LLM.
    * @returns {Promise<Source[]>} - A list of candidate sources.
    */
   async getCandidatesByFunctionName(llmIdentifiedFunctionName) {
      const candidates = this.sources;
      let sourcesFromDescription = [];
      if (llmIdentifiedFunctionName) {
         sourcesFromDescription = candidates.filter((source) =>
            ciEquals(source.getFullExportName(), llmIdentifiedFunctionName),
         );
         if (llmIdentifiedFunctionName.includes(".")) {
            sourcesFromDescription = candidates.filter((source) =>
               source.getFullExportName().toLowerCase().endsWith(llmIdentifiedFunctionName.toLowerCase())
            );
         }
         if (sourcesFromDescription.length === 0) {
            const normalizedName = llmIdentifiedFunctionName.split(".").pop().toLowerCase();
            sourcesFromDescription = candidates.filter(
               (c) =>
                  c.getFullExportName().toLowerCase().endsWith(llmIdentifiedFunctionName.toLowerCase()) ||
                  ciEquals(c.callable.name, normalizedName) ||
                  ciEquals(c.callable.exportName, normalizedName),
            );
         }
      }
      return sourcesFromDescription;
   }

   toJSON() {
      return {
         moduleName: this.moduleName,
         sources: this.sources.length,
         sourcesInScope: this.sourcesInScope.length,
         sourcesOutOfScope: this.sourcesOutOfScope.length,
         errors: this.errors
      }
   }
}

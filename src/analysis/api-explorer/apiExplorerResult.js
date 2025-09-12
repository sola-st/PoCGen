import Source from "../../models/source.js";

/**
 * Class representing the result of an API exploration.
 */
export default class ApiExplorerResult {
   /**
    * List of error messages encountered during the API exploration.
    * @type {string[]}
    */
   errors = [];

   /**
    * List of events recorded during the API exploration.
    * @type {Object[]}
    */
   events = [];

   /**
    * The API module being explored.
    * @type {ApiModule}
    */
   apiModule;

   /**
    * List of globally exported API nodes.
    * @type {ApiNode[]}
    */
   exportedGlobals = [];

   /**
    * List of source objects representing the flattened structure of the API.
    * @type {Source[]}
    * @private
    */
   #sources;

   /**
    * Flattens the tree-like structure of the exported callables into a list of callables
    *
    * @returns {Source[]} the list of callables
    */
   getSources() {
      if (!this.apiModule) {
         throw new Error("apiModule is undefined");
      }
      this.#sources = [];
      for (const apiNode of this.apiModule.exports) {
         if (apiNode.type !== undefined) {
            this.flattenObject(apiNode, false);
         } else {
            this.flattenObject(apiNode, false);
         }
      }
      for (const apiNode of this.exportedGlobals) {
         this.flattenObject(apiNode, true);
      }
      return this.#sources;
   }

   /**
    * Flattens the given object into a list of callables.
    *
    * @param {ApiNode|ApiFunction} currentObject - The current object to flatten.
    * @param {boolean} isGlobal - Indicates if the current object is a global export.
    * @param {ApiNode[]|ApiFunction[]} parentChain - The chain of parent objects leading to the current object.
    */
   flattenObject(currentObject, isGlobal, parentChain = []) {
      if (!currentObject) {
         throw new Error("currentObject is undefined");
      }
      if (Array.isArray(currentObject.protoFunctions)) {
         for (const child of currentObject.protoFunctions) {
            this.flattenObject(child, isGlobal, [...parentChain, currentObject]);
         }
         if (Array.isArray(currentObject.children)) {
            for (const child of currentObject.children) {
               this.flattenObject(child, isGlobal, [...parentChain, currentObject]);
            }
         }
         // Dont add the class declaration itself
         if (
            currentObject.type === "ClassDeclaration" ||
            currentObject.type === "ClassExpression"
         ) {
            return;
         }
      }

      if (currentObject.location) {
         this.#sources.push(
            new Source(
               parentChain,
               currentObject,
               this.apiModule,
               isGlobal,
               true,
            ),
         );
      }
      if (Array.isArray(currentObject.children)) {
         for (const child of currentObject.children) {
            this.flattenObject(child, isGlobal, [...parentChain, currentObject]);
         }
      }
   }
}

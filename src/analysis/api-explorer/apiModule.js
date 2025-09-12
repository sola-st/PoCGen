/**
 * Represents an API module.
 */
export default class ApiModule {
   /**
    * The name of the module.
    * @type {string}
    */
   importName;

   /**
    * Indicates if the module is an ES module.
    * @type {boolean}
    */
   isESM;

   /**
    * The exports of the module.
    * @type {any[]}
    */
   exports;

   /**
    * Indicates if this is the main module.
    * @type {boolean}
    */
   isMainModule = false;

   /**
    * The relative path of the module.
    * @type {string}
    */
   relativePath;

   /**
    * Creates an ApiModule instance from a file.
    * @param {Object} npmPackage - The npm package information.
    * @param {string} relativePath - The relative file path.
    * @returns {ApiModule} The created ApiModule instance.
    */
   static fromFile(npmPackage, relativePath) {
      const apiModule = new ApiModule();
      apiModule.isESM = relativePath.endsWith(".mjs");
      apiModule.importName = relativePath.replace(/\.m?js$/, "");
      if (apiModule.importName === "index") {
         apiModule.importName = "";
      }
      apiModule.importName = apiModule.relativePath = relativePath;
      return apiModule;
   }
}

import path, {relative} from "node:path";
import {isDirectory} from "../utils/utils.js";
import {join} from "path";
import {existsSync, readdirSync, readFileSync} from "node:fs";
import ApiModule from "../analysis/api-explorer/apiModule.js";
import fs from "fs";

export default class NpmProject {

   #cachedFiles = null;

   constructor(baseDir) {
      this.nmModulePath = baseDir;
      this.pckgJson = JSON.parse(
         readFileSync(join(this.nmModulePath, "package.json"), "utf-8"),
      );
   }

   /**
    * Retrieves the main entry point of the npm project.
    *
    * @returns {string|null} The normalized entry point file path, or null if not found.
    */
   get main() {
      let entryPoint = path.normalize(this.pckgJson.main ?? "index.js");
      if (this.files.includes(entryPoint)) {
         return entryPoint;
      }
      if (!entryPoint.endsWith(".js")) {
         if (this.files.includes(entryPoint + ".js")) {
            return entryPoint + ".js";
         }
      }
      // Check if entry point is directory
      if (isDirectory(join(this.nmModulePath, entryPoint))) {
         entryPoint = join(entryPoint, "index.js");
         if (this.files.includes(entryPoint)) {
            return entryPoint;
         }
      }
      return null;
   }

   getApiModule(relativePath) {
      const apiModule = new ApiModule();

      if (relativePath === this.main) {
         apiModule.isMainModule = true;
         apiModule.importName = moduleName;
      } else {
         apiModule.isMainModule = false;
         if (apiModule.isESM) {
            apiModule.importName = join(moduleName, relativePath);
         } else {
            if (relativePath.endsWith("index.js")) {
               apiModule.importName = join(moduleName, relativePath.replace(
                  /\/index\.js$/,
                  "",
               ));
            } else {
               apiModule.importName = join(moduleName, relativePath.replace(/\.js$/, ""));
            }
         }
      }

   }

   /**
    * ```json
    * {
    *   "exports": "./index.js"
    * }
    *
    * {
    *   "name": "my-package",
    *   "exports": {
    *     ".": "./lib/index.js",
    *     "./lib": "./lib/index.js",
    *     "./lib/index": "./lib/index.js",
    *     "./lib/index.js": "./lib/index.js",
    *     "./feature": "./feature/index.js",
    *     "./lib/*": "./lib/*.js",
    *     "./lib/*.js": "./lib/*.js",
    *     "./feature": "./feature/index.js",
    *     "./feature/*": "./feature/*.js",
    *     "./feature/*.js": "./feature/*.js",
    *     "./package.json": "./package.json"
    *   }
    * }
    * ```
    *
    * @return {string[]}
    */
   get exports() {
      const exportEntries = [];
      if (!this.pckgJson.exports) {
         return exportEntries;
      }
      if (typeof this.pckgJson.exports === "string") {
         exportEntries.push("");
      } else {
         for (const key of Object.keys(this.pckgJson.exports)) {
            if (key.endsWith("package.json")) {
               continue;
            }
            // Ignore if value is null
            if (this.pckgJson.exports[key] === null) {
               continue;
            }
            // Special case "*.*" entries
            // todo: replace with glob
            if (!fs.existsSync(join(this.nmModulePath, key)) && key.includes("*")) {
               const files = this.files.filter((f) => f.startsWith(key.replace("*", "")));
               exportEntries.push(...files);
               continue;
            }
            exportEntries.push(key);
         }
      }
      return exportEntries;
   }

   /**
    * Retrieves the list of exported files for the npm project.
    *
    * @returns {string[]} An array of relative paths to the exported files.
    */
   get relativePaths() {
      let relativePaths = Array.from(this.files);
      console.info(
         `Found ${relativePaths.length} source files in ${this.nmModulePath}`,
      );
      const entryPoint = this.main;
      if (!entryPoint) {
         console.warn(`Invalid main field: ${this.pckgJson.main}`);
      } else {
         // Put entrypoint at the beginning of the list
         relativePaths = relativePaths.filter((f) => f !== entryPoint);
         relativePaths.unshift(entryPoint);
      }
      return relativePaths;
   }

   /**
    * Retrieves the list of source files for the npm project.
    *
    * @returns {string[]} An array of relative paths to the source files.
    */
   get files() {
      if (this.#cachedFiles === null) {
         this.#cachedFiles = this.#getOwnSourceFiles();
      }
      return this.#cachedFiles;
   }

   /**
    * Retrieves the source files from a specified package.
    *
    * @returns {string[]} An array of relative paths to the source files.
    */
   #getOwnSourceFiles() {
      const relativePaths = [];

      const self = this;

      function readDir(directoryName) {
         const files = readdirSync(directoryName, {withFileTypes: true});
         files.forEach((dirent) => {
            const filePath = join(directoryName, dirent.name);
            if (dirent.isDirectory()) {
               if (
                  !["docs", "browser", "demo", "node_modules"].includes(dirent.name) &&
                  !dirent.name.includes("test")
               ) {
                  readDir(filePath);
               }
            } else if (/\.(js|mjs|cjs)$/i.test(filePath)) {
               if (
                  dirent.name.endsWith(".test.js") ||
                  dirent.name.endsWith(".spec.js")
               ) {
                  return;
               }
               if (dirent.name.endsWith(".min.js")) {
                  // Check if corresponding non-minified file exists
                  const nonMinFile = filePath.replace(/.min.js$/, ".js");
                  if (nonMinFile.endsWith(".js") && existsSync(nonMinFile)) {
                     return;
                  }
               }
               const relativePath = relative(self.nmModulePath, filePath);
               relativePaths.push(relativePath);
            }
         });
      }

      readDir(this.nmModulePath);
      return relativePaths;
   }

}

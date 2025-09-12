import {fork} from "child_process";
import {join} from "path";
import {existsSync, readdirSync} from "node:fs";
import ApiExplorerResult from "./apiExplorerResult.js";
import {relative} from "node:path";
import NpmProject from "../../npm/npmProject.js";
import ApiExplorerList from "../../runners/apiExplorerList.js";

/**
 * @typedef {import("child_process").ForkOptions} ForkOptions
 */

/**
 * @typedef {Object} ExplorerConfig
 * @property {ForkOptions?} forkOptions
 * @property {boolean?} onlyEntryPoint - Only return files defined in "main" or "exports" field.
 */

/**
 * Retrieves the exports from a specified package.
 *
 * @param {string} nmPath - The path to the node\_modules directory.
 * @param {string} moduleName - The name of the module to get exports from.
 * @param {ExplorerConfig} config - Optional environment variables to pass to the child process.
 * @returns {Promise<ApiExplorerList>} A promise that resolves to an array of ApiExplorerResult objects.
 */
export async function getExportsFromPackage(nmPath, moduleName, config = undefined) {
   const apiExplorerResults = new ApiExplorerList();
   apiExplorerResults.moduleName = moduleName;

   const nmModulePath = join(nmPath, moduleName);
   const npmProject = new NpmProject(nmModulePath);

   const exportKeys = npmProject.exports;
   if (exportKeys.length > 0) {
      // Add "main" to exports if it is not already included
      if (npmProject.main && !exportKeys.includes(npmProject.main)) {
         exportKeys.push("");
      }
      //  For all paths join with module name
      const exportNames = exportKeys.map((path) => join(moduleName, path));

      for (const exportName of new Set(exportNames)) {
         try {
            const apiExplorerResult = await getExportsFromFile(exportName, nmPath, moduleName, config.forkOptions);
            console.info(`Got exports from ${exportName}`);
            apiExplorerResult.apiModule.importName = moduleName;
            apiExplorerResults.push(apiExplorerResult);
         } catch (e) {
            console.error(`Error getting exports from ${exportName}: ${e}`);
         }
      }

      return apiExplorerResults;
   }

   let relativePaths = npmProject.relativePaths;
   if (config?.onlyEntryPoint && npmProject.main) {
      relativePaths.length = 0;
      relativePaths.push(npmProject.main);
   }

   for (const relativePath of new Set(relativePaths)) {
      try {
         const apiExplorerResult = await getExportsFromFile(join(moduleName, relativePath), nmPath, moduleName, config.forkOptions);
         console.info(`Got ${apiExplorerResult.apiModule?.exports?.length} exports from ${relativePath}`);
         if (relativePath === npmProject.main) {
            apiExplorerResult.apiModule.isMainModule = true;
            apiExplorerResult.apiModule.importName = moduleName;
         } else {
            apiExplorerResult.apiModule.isMainModule = false;
            if (apiExplorerResult.apiModule.isESM) {
               apiExplorerResult.apiModule.importName = join(moduleName, relativePath);
            } else {
               if (relativePath.endsWith("index.js")) {
                  apiExplorerResult.apiModule.importName = join(moduleName, relativePath.replace(
                     /\/index\.js$/,
                     "",
                  ));
               } else {
                  apiExplorerResult.apiModule.importName = join(moduleName, relativePath.replace(/\.js$/, ""));
               }
            }
         }

         apiExplorerResults.push(apiExplorerResult);
      } catch (e) {
         console.error(`Error getting exports from ${relativePath}: ${e}`);
      }
   }
   return apiExplorerResults;
}

/**
 * Retrieves the exports from a specified file.
 *
 * @param {string} relativePath - Path to the file to get exports from.
 * @param {string} nmPath - Path to the node_modules directory.
 * @param {string} moduleName - Name of the module to get exports from.
 * @param {ForkOptions} forkOptions - Environment variables to pass to the child process. If undefined, NODE_PATH is set to nmPath.
 * @returns {Promise<ApiExplorerResult>} A promise that resolves to an ApiExplorerResult object.
 */
export async function getExportsFromFile(
   relativePath,
   nmPath,
   moduleName,
   forkOptions = undefined,
) {
   const nmModulePath = join(nmPath, moduleName);
   if (!existsSync(nmModulePath)) {
      throw new Error(`Module ${moduleName} not found at ${nmModulePath}`);
   }

   const apiExplorerResult = await new Promise((resolve, reject) => {
      const scriptPath = join(import.meta.dirname, "apiExplorer.js");
      if (!existsSync(nmPath)) {
         reject(new Error(`nmPath expected at ${nmPath} not found`));
         return;
      }
      const childOptions = forkOptions === undefined
         ? {
            env: {...process.env, NODE_PATH: nmPath},
         }
         : forkOptions;
      childOptions.cwd = nmPath;
      const apiExplorer = fork(
         scriptPath,
         [],
         childOptions,
      );
      let receivedResult = false;
      apiExplorer.send([nmModulePath, nmPath, moduleName, relativePath]);
      apiExplorer.on("message", (result) => {
         receivedResult = true;
         const apiExplorerResult = new ApiExplorerResult();
         for (const key in result) {
            apiExplorerResult[key] = result[key];
         }
         resolve(apiExplorerResult);
         process.kill(apiExplorer.pid);
      });
      apiExplorer.on("exit", (code) => {
         if (receivedResult) {
            return;
         }
         reject(new Error(`Exited with code ${code}`));
      });
      apiExplorer.on("error", (err) => {
         reject(err);
         process.kill(apiExplorer.pid);
      });
   });
   if (apiExplorerResult.errors.length > 0) {
      console.warn(
         `Errors in ${relativePath}: ${JSON.stringify(apiExplorerResult.errors)}`,
      );
   }
   return apiExplorerResult;
}

/**
 * Retrieves the source files from a specified directory.
 *
 * @param {string} dir - The directory to search for source files.
 * @returns {string[]} An array of relative paths to the source files.
 */
function getOwnSourceFiles(dir) {
   const jsFiles = [];

   function readDir(directoryName) {
      const files = readdirSync(directoryName, {withFileTypes: true});
      files.forEach((dirent) => {
         const filePath = join(directoryName, dirent.name);
         if (dirent.isDirectory()) {
            if (
               /* dirent.name !== "docs" &&
                dirent.name !== "browser" &&
                dirent.name !== "demo" &&
                dirent.name !== "node_modules" &&*/
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
            const relativePath = relative(dir, filePath);
            jsFiles.push(relativePath);
         }
      });
   }

   readDir(dir);
   return jsFiles;
}

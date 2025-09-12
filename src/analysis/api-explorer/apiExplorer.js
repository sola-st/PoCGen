import {esc, IgnoredError, rmPrefix, runAsyncWithTimeout} from "../../utils/utils.js";
import LocationRange from "../../models/locationRange.js";
import ApiFunction from "./apiFunction.js";
import {createRequire} from "node:module";
import ApiExplorerResult from "./apiExplorerResult.js";
import ApiModule from "./apiModule.js";
import {join} from "path";
import {readFileSync} from "node:fs";
import Location from "../../models/location.js";
import {extractClassMethods} from "../../utils/parserUtils.js";
import parser from "@babel/parser";
import {relative} from "node:path";
import ApiNode from "./apiNode.js";

process.on(
   "message",
   async ([nmModulePath, nmPath, moduleName, relativePath]) => {
      const apiExplorer = await new ApiExplorer(
         nmModulePath,
         nmPath,
         moduleName,
         relativePath,
      );
      await apiExplorer.init();
      try {
         const result = await apiExplorer.explore();
         process.send(result);
      } catch (e) {
         console.error(`Unexpected Error in ${import.meta.url}`);
         console.error(e);
         const result = new ApiExplorerResult();
         result.errors.push(e.stack);
         process.send(result);
      }
   },
);

/**
 * Retrieves the location of a function.
 * @type {Function}
 */
const {getFunctionLocation} = createRequire(import.meta.url)(
   "function_location",
);

/**
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("../../models/locationRange").default} LocationRange
 */

/**
 * Class to explore API modules and gather information about their exports.
 *
 * Inspired by {@link https://github.com/neu-se/testpilot2/blob/main/src/exploreAPI.ts}
 */
export class ApiExplorer {
   /**
    * Holds the result of the API exploration.
    * @type {ApiExplorerResult}
    */
   apiExplorerResult = new ApiExplorerResult();

   /**
    * Represents the API module being explored.
    * @type {ApiModule}
    */
   apiModule = new ApiModule();

   /**
    * Creates an instance of ApiExplorer.
    *
    * @param {string} nmModulePath - The path to the node module.
    * @param {string} nmPath - The path to the node modules directory.
    * @param {string} moduleName - The name of the module.
    * @param {string} relativePath - The relative path to the module.
    */
   constructor(nmModulePath, nmPath, moduleName, relativePath) {
      this.nmModulePath = nmModulePath;
      this.nmPath = nmPath;
      this.moduleName = moduleName;
      this.relativePath = relativePath;
      global.require = createRequire(this.nmPath);
      this.globalKeys = Object.getOwnPropertyNames(global);
   }

   async init() {
      process.on("uncaughtException", (err) => {
         console.error(err);
         if (!(err instanceof IgnoredError)) {
            this.apiExplorerResult.errors.push(err.stack);
         }
      });
   }

   /**
    * Explores the API module and gathers information about its exports.
    *
    * @returns {Promise<ApiExplorerResult>} A promise that resolves to the result of the API exploration.
    */
   async explore() {
      let module;
      const moduleImportName = this.relativePath; // join(this.nmModulePath, this.relativePath);
      try {
         module = require(moduleImportName);
         this.apiModule.relativePath = relative(this.nmPath, require.resolve(moduleImportName));
         this.apiModule.isESM = false;
      } catch (e) {
         try {
            module = await runAsyncWithTimeout("await import('" + moduleImportName + "')", 10000, true);
            this.apiModule.relativePath = relative(this.nmPath, rmPrefix(import.meta.resolve(moduleImportName), "file://"));
            this.apiModule.isESM = true;
            e = null;
         } catch (e0) {
            console.error(`Error loading module ${moduleImportName}: ${e0}`);
            e = e0;
         }
         if (e != null && !(e instanceof IgnoredError)) {
            this.apiExplorerResult.errors.push(e.message);
         }
      } finally {
         const newGlobalKeys = Object.getOwnPropertyNames(global).filter(s => !this.globalKeys.includes(s));
         for (const key of newGlobalKeys) {
            const value = global[key];
            const res = this.addObject(key, value, []);
            if (res) {
               this.apiExplorerResult.exportedGlobals.push(res);
            }
         }
      }
      if (module) {
         const result = this.addObject(undefined, module, []);
         result.isModuleRoot = true;
         this.apiModule.exports = [result];
      } else {
         this.apiModule.exports = [];
      }
      this.apiExplorerResult.apiModule = this.apiModule;
      return this.apiExplorerResult;
   }

   /**
    * Adds an object to the API exploration result.
    *
    * @param {string} newObjectExportName - The name of the new object export.
    * @param {Object|Function} newObject - The new object to add.
    * @param {Array} parentChain - The chain of parent objects to detect circular references.
    * @returns {ApiNode|null} The API node representing the added object.
    */
   addObject(newObjectExportName, newObject, parentChain) {
      if (newObject === null || newObject === undefined) {
         return null;
      }

      if (parentChain.includes(newObject)) {
         console.warn(`Circular reference detected: ${parentChain.map(s => s.name).join(" -> ")} <-> ${newObjectExportName}`);
         return null;
      }

      const children = [];

      // Array?
      if (Array.isArray(newObject)) {
         for (let i = 0; i < newObject.length; i++) {
            const value = newObject[i];
            if (!value || value === newObject) {
               continue;
            }
            const o = this.addObject(i.toString(), value, [...parentChain, newObject]);
            if (o) {
               children.push(o);
            }
         }
         return new ApiNode(newObjectExportName, children);
      }

      if (typeof newObject === "function") {
         if (newObjectExportName === "constructor") {
            // Ignoring constructor
            return null;
         }
         const apiFunction = this.fromFunction(newObject);
         if (apiFunction) {
            return this.addCallable(newObjectExportName, newObject, parentChain);
         }
         // It can happen that the apiFunction is null (for example for native or out of scope function)
         // In this case we won't return here and add the function as a normal ApiNode and inspect its children
      }

      if (typeof newObject === "function" || typeof newObject === "object") {
         for (const [name, value] of getProperties(newObject)) {
            if (!value || value === newObject) {
               continue;
            }
            const o = this.addObject(name, value, [...parentChain, newObject]);
            if (o) {
               children.push(o);
            }
         }
         return new ApiNode(newObjectExportName, children);
      }

      return null;
   }

   /**
    * Adds a callable function to the API exploration result.
    * @param {string} newObjectExportName - The name of the callable export.
    * @param {Function} callable - The callable function to update.
    * @param {Array} parentChain - The chain of parent objects to detect circular references.
    * @returns {ApiFunction|null} The resulting callable function or null if not applicable.
    */
   addCallable(newObjectExportName, callable, parentChain) {
      const apiFunction = this.fromFunction(callable);

      // Some modules only export one wrapper function with an empty prototype. An example is the 'axios' module.
      // In this case we want to include all inner functions
      const children = [];
      for (const [name, value] of getProperties(callable)) {
         if (
            name === "prototype" ||
            value === callable
         ) {
            continue;
         }
         const result = this.addObject(name, value, [...parentChain, callable]);
         if (result) {
            children.push(result);
         }
      }
      if (children.length > 0) {
         apiFunction.children = children;
      }

      // Parse the code to get the signature
      const nodeType = apiFunction.node?.type;
      switch (nodeType) {
         // ES6 Class Syntax
         case "ClassExpression":
         case "ClassDeclaration":
            const classMethods = [];
            for (const propMethodName of Object.getOwnPropertyNames(
               callable.prototype,
            )) {
               if (propMethodName === "constructor") {
                  // apiFunction.location refers to the constructor, but "toString" returns the complete class definition
                  // i.e. the full location is not correct
                  // We first need to extract the constructor code from the class definition
                  const fileContent = readFileSync(join(this.nmPath, apiFunction.location.filePath), "utf-8");
                  const ast = parser.parse(fileContent, {
                     errorRecovery: true,
                     sourceFilename: apiFunction.location.filePath,
                  });
                  const constructorNode = extractClassMethods(ast).map(s => s.node).findLast((node) =>
                     node.kind === "constructor" &&
                     LocationRange.fromBabelNode(node).containsPoint(apiFunction.location));
                  if (constructorNode) {
                     const constructorSrc = fileContent.slice(constructorNode.start, constructorNode.end);
                     const classMethod = new ApiFunction(constructorSrc, "constructor",
                        LocationRange.fromBabelNode(constructorNode),
                        undefined, constructorNode, []);
                     classMethods.push(classMethod);
                  }
                  continue;
               }
               const property = Object.getOwnPropertyDescriptor(
                  callable.prototype,
                  propMethodName,
               );
               for (const fn of [property.value, property.get, property.set]) {
                  if (typeof fn !== "function") {
                     continue;
                  }
                  const innerMethod = this.fromFunction(fn);
                  if (!innerMethod) {
                     continue;
                  }
                  classMethods.push(innerMethod.copyExportName(propMethodName));
               }
            }
            apiFunction.protoFunctions = classMethods;
            return apiFunction.copyExportName(newObjectExportName);
         case "FunctionExpression":
         case "FunctionDeclaration":
            // Arrow functions do not have a prototype property so do not check for inner functions
            if (callable.prototype === undefined) {
               return apiFunction.copyExportName(newObjectExportName);
            }
            // Constructor Function (Pre-ES6)
            if (callable.prototype && callable.prototype !== {}) {
               const protoFunctions = [];
               for (const [propMethodName, innerCallable] of getProperties(
                  callable.prototype,
               )) {
                  if (
                     propMethodName === "constructor" ||
                     typeof innerCallable !== "function" ||
                     innerCallable === callable // Avoid circular references
                  ) {
                     continue;
                  }
                  const apiFunction = this.fromFunction(innerCallable);
                  if (apiFunction !== null) {
                     protoFunctions.push(apiFunction.copyExportName(propMethodName));
                  }
               }
               if (protoFunctions.length > 0) {
                  apiFunction.protoFunctions = protoFunctions;
                  return apiFunction.copyExportName(newObjectExportName);
               }
            }
            // Normal function declaration
            return apiFunction.copyExportName(newObjectExportName);
         default:
            return apiFunction.copyExportName(newObjectExportName);
      }
   }

   /**
    * Converts a function to an ApiFunction object.
    *
    * @param {Function} fn - The function to convert.
    * @param {Node} [node=undefined] - The AST node representing the function.
    * @returns {ApiFunction|null} - The ApiFunction object or null if the function is native, out of scope, or a parser error occurred.
    */
   fromFunction(fn, node = undefined) {
      const code = Function.prototype.toString.apply(fn);
      const name = fn.name;
      const fnLoc = getFunctionLocation(fn);
      if (!fnLoc.filePath.startsWith(this.nmPath)) {
         if (fnLoc.filePath) {
            // We assume that the vulnerable source will be declared in the module as specified in the vulnerability database
            console.debug(
               `Function ${name} (${JSON.stringify(fnLoc.filePath)}) is out of scope`,
            );
         }
         return null;
      }
      const location = new Location(
         relative(this.nmPath, fnLoc.filePath),
         fnLoc.startLine,
         fnLoc.startColumn,
      );
      try {
         const apiFunction = new ApiFunction(
            code,
            name,
            LocationRange.fromLocation(location, code),
            undefined,
            node,
         );
         if (apiFunction.isNative) {
            return null;
         }
         return apiFunction;
      } catch (e) {
         console.error(`Error parsing callable: ${fn.toString()}`);
         console.log(e);
         return null;
      }
   }
}

/**
 * Get properties of an object
 * @param {object} obj
 * @returns {[string, unknown][]}
 */
function getProperties(obj) {
   const props = {};
   for (const propName of Object.getOwnPropertyNames(obj)) {
      try {
         const propertyDescriptor = Object.getOwnPropertyDescriptor(obj, propName);
         if (!propertyDescriptor) {
            continue;
         }
         if (propertyDescriptor.value) {
            props[propName] = propertyDescriptor.value;
         }
         if (propertyDescriptor.set) {
            props[propName] = propertyDescriptor.set;
         }
         if (propertyDescriptor.get) {
            try {
               props[propName] = obj[propName];
            } catch (e) {
               console.warn(`Error getting property ${esc(propName)}`);
               props[propName] = propertyDescriptor.get;
            }
         }
      } catch (e) {
         console.error(`Error getting property ${esc(propName)}`);
      }
   }

   // Also add properties from prototype
   const proto = Object.getPrototypeOf(obj);
   if (proto && proto !== Object.prototype && proto !== Function.prototype) {
      for (const propName of Object.getOwnPropertyNames(proto)) {
         try {
            const desc = Object.getOwnPropertyDescriptor(proto, propName);
            if (!desc || !desc.value) {
               continue;
            }
            props[propName] = desc.value;
            // props[propName] = obj[propName];
         } catch (e) {
            console.error(`Error getting property "${propName}"`, e);
         }
      }
   }
   return Object.entries(props);
}

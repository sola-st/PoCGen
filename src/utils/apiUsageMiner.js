import LocationRange from "../models/locationRange.js";
import {extractSourceCode, extractTripleBackticks, recListFiles} from "./utils.js";
import {readFileSync} from "node:fs";
import {getAllCalls, getEnclosingStatement} from "./parserUtils.js";
import {parse} from "@babel/parser";

export default class ApiUsageMiner {

   /**
    * Creates an instance of ApiUsageMiner.
    *
    * @param {string} baseDir - The base directory to search for documentation and test files.
    * @param {Source} source - The source object containing information about the callable.
    */
   constructor(baseDir, source) {
      this.baseDir = baseDir;
      this.source = source;
      this.results = new Set();
   }

   /**
    * Find all documentation files.
    *
    * @returns {string[]} - An array of documentation files.
    */
   get docFiles() {
      return recListFiles(this.baseDir, /README(\.txt|\.md)?$|\.md$/i);
   }

   /**
    * Find all files with test cases.
    *
    * @returns {string[]} - An array of test files.
    */
   get testFiles() {
      return [
         ...recListFiles(this.baseDir, /.*test\.js$/),
         ...recListFiles(this.baseDir, /.*test.*/, "dirOnly").map((dir) => recListFiles(dir, /.*\.js$/)).flat(),
      ];
   }

   /**
    * Retrieves the content of the project's README file if it exists.
    *
    * @returns {string|null} - The content of the README file or null if not found.
    */
   get readMe() {
      const readMe = this.docFiles.find((f) => f.match(/README(\.txt|\.md)?/i));
      if (readMe) {
         return readFileSync(readMe, "utf-8");
      }
      return null;
   }

   /**
    * Collect all snippets from documentation and test files that have a call to the source function.
    *
    * @returns {string[]} - List of crawled snippets.
    */
   search() {
      const search = {
         functionName: "",
         patterns: []
      }
      if (this.source.callable.exportName === "default" && this.source.callable.name?.length > 0) {
         // Transpiled ES module
         search.functionName = this.source.callable.name;
      } else {
         if (this.source.callable.exportName?.length > 0) {
            search.functionName = this.source.callable.exportName;
         } else {
            if (this.source.callable.name?.length > 0) {
               // If the source is not exported, search for the source name
               search.functionName = this.source.callable.name;
            }

            if (this.source.callable.isModuleRoot) {
               search.patterns.push(new RegExp(`(import)|(require)\s*\\(\s*["']${this.source.module.importName}["']\s*\\)`));
            }
         }
      }
      if (search.functionName.length > 0) {
         search.patterns.push(new RegExp(`${search.functionName}\s*\\(`));
      }
      if (search.functionName.length === 0 && search.patterns.length === 0) {
         return [];
      }

      for (const docFile of this.docFiles) {
         const snippets = extractTripleBackticks(readFileSync(docFile, "utf-8"));
         for (const snippet of snippets) {
            try {
               const calls = getCalls(snippet, search.functionName);
               if (calls.length > 0) {
                  this.results.add(snippet);
               }
            } catch (e) {
               console.warn(`Could not parse snippet in ${docFile} ${e.message}.`);
            }
         }

         if (this.results.size === 0 && search.patterns.length > 0) {
            // Fall back to pattern search
            for (const snippet of snippets) {
               if (search.patterns.some((pattern) => pattern.test(snippet))) {
                  this.results.add(snippet);
               }
            }
         }
      }
      for (const testFile of this.testFiles) {
         try {
            const content = readFileSync(testFile, "utf-8");
            const r = getCalls(content, search.functionName);
            for (const snippet of r) {
               this.results.add(snippet);
            }
         } catch (e) {
            console.error(`Error in test file ${testFile}: ${e.message}`);
         }
      }
      return Array.from(this.results);
   }
}

/**
 * Try to parse the content and extract the source code of the callName
 *
 * @param {string} content - The content to parse.
 * @param {string} callName - The name of the function to search for.
 * @returns {string[]} - An array of source code snippets.
 */
function getCalls(content, callName) {
   const results = [];
   const ast = parse(content, {
      plugins: ["typescript", "decorators-legacy"],
      errorRecovery: true,
      sourceType: "module",
   });
   const calls = getAllCalls(ast);
   for (const call of calls) {
      if (callName === call.node.callee?.name || callName === call.node.callee.property?.name) {
         let locationCallNode = LocationRange.fromBabelNode(call.node);
         let enclosingStatement = getEnclosingStatement(ast, locationCallNode);
         if (enclosingStatement.node.type === "ExpressionStatement") {
            enclosingStatement = enclosingStatement.parentPath;
         }
         let locationEnclosingNode = LocationRange.fromBabelNode(enclosingStatement.node);

         results.push(extractSourceCode(locationEnclosingNode, content));
      }
   }
   return results;
}






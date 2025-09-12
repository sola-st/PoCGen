import {config} from "dotenv";
import {colorize} from "./logging.js";
import {copyFileSync, mkdirSync, readdirSync, statSync,} from "node:fs";
import {createHash} from "node:crypto";
import yauzl from "yauzl";
import * as vm from "node:vm";
import ptimeout from "promise.timeout";
import {existsSync} from "fs";
import {basename, dirname, extname, join} from "path";

/**
 * @typedef {import("node:vm").RunningScriptOptions} RunningScriptOptions
 */

/**
 * Custom error class to represent ignored errors.
 */
export class IgnoredError extends Error {
}

/**
 * Custom error class for handling timeout errors.
 */
export class TimeoutError extends Error {
   /**
    * Creates an instance of TimeoutError.
    *
    * @param {number[]|undefined} s - The start time of the function execution.
    */
   constructor(s) {
      super();
      this.message = "Function timed out";
      if (s) {
         const end = process.hrtime(s);
         this.message += ` after ${end[0] * 1e3 + end[1] / 1e6} ms`;
      }
      Error.captureStackTrace(this, TimeoutError)
   }
}

/**
 * Pauses execution for a specified number of milliseconds.
 *
 * @param {number} ms - The number of milliseconds to sleep.
 * @returns {Promise<void>} - A promise that resolves after the specified time.
 */
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Escapes the given value by converting it to a JSON string if it is truthy.
 *
 * @param {any} s - The value to escape.
 * @returns {string|*} - The escaped value as a JSON string, or the original value if falsy.
 */
export const esc = (s) => (s ? JSON.stringify(s) : s);

/**
 * A reference to the AsyncFunction constructor.
 *
 * @type {Function}
 */
export const AsyncFunction = async function () {
}.constructor;

/**
 * Retrieves the value of an environment variable.
 *
 * @param {string} key - The name of the environment variable to retrieve.
 * @returns {string} - The value of the environment variable.
 * @throws {Error} - Throws an error if the environment variable is not found.
 */
export function env(key) {
   const value = process.env[key];
   if (!value) {
      throw new Error(`${key} not found in environment variables`);
   }
   return value;
};

/**
 * Recursively copy files from the source directory to the destination directory.
 *
 * @param {string} src - The source directory path.
 * @param {string} dst - The destination directory path.
 */
export function recCopy(src, dst) {
   const entries = readdirSync(src, {withFileTypes: true});
   mkdirSync(dst, {recursive: true});
   for (let entry of entries) {
      const srcPath = join(src, entry.name);
      const dstPath = join(dst, entry.name);
      if (entry.isDirectory()) {
         recCopy(srcPath, dstPath);
      } else {
         copyFileSync(srcPath, dstPath);
      }
   }
}

/**
 * Converts a kebab-case string to camelCase.
 *
 * @param s {string} - The kebab-case string to convert.
 * @returns {string} - The converted camelCase string.
 */
export const kebabToCamel = (s) => {
   return s.replace(/-([a-z])/g, (g) => g[1].toUpperCase());
};

/**
 * Get a valid identifier from a string.
 *
 * @param {string} id - The string to convert to a valid identifier
 * @returns {string} - A valid identifier
 */
export const getIdentifierName = (id) => {
   let result = id.split("/").pop() // Scoped package names
      .trim()
      .replace(/[^\w$]+/g, "");
   if (/^\d/.test(result)) {
      result = "_" + result;
   }
   return result;
};

export const errorSerializer = (e) => {
   return {
      message: e.message,
      stack: e.stack,
      name: e.name,
      cause: e.cause,
   };
};

export function overwriteSerializers() {
   Set.prototype.toJSON = function () {
      return Array.from(this);
   };

   // Make sure errors are properly serialized
   Error.prototype.toJSON = function () {
      return errorSerializer(this);
   };

   Array.prototype.toString = function () {
      return JSON.stringify(this);
   };
}

/**
 * Joins the elements of the array into a single string, ensuring no extra delimiters.
 *
 * @param {...string} arr - The array of strings to join.
 * @returns {string} - The joined string without extra delimiters.
 * @throws {Error} - Throws an error if the first argument is not a string or the second argument is not an array.
 */
export function joinTexts(...arr) {
   const delim = "\n";
   return arr
      .map(str => str.replace(new RegExp(`^${delim}|${delim}$`, 'g'), '')) // Remove leading/trailing delimiters
      .join(delim);
}

/**
 * Initializes the environment and sets up console logging functions.
 *
 * @param {Object?} opts - The options for initialization.
 * @param {boolean} [opts.verbose] - If true, enables verbose debug logging.
 * @throws {Error} - Throws an error if required binaries are not found in PATH.
 */
export function loadEnv(opts) {
   config();

   overwriteSerializers();

   console.debug = opts?.verbose
      ? (msg) => {
         console.log(colorize.gray(msg));
      }
      : () => {
      };
   console.success = function (msg) {
      console.log(colorize.green(msg));
   };
   console.info = function (msg) {
      console.log(colorize.blue(msg));
   };
   console.warn = function (msg) {
      console.log(colorize.yellow(msg));
   };
   console.error = function (msg) {
      console.log(colorize.red(msg));
   };

   console.debug(JSON.stringify(opts, null, 2));
}

/**
 * Checks if the given string is a valid JavaScript identifier.
 *
 * @param {string} n - The string to check.
 * @returns {boolean} - True if the string is a valid identifier, false otherwise.
 */
export function isValidId(n) {
   return /^[a-zA-Z_$][a-zA-Z_$0-9]*$/.test(n);
}

/**
 * Returns the first non-empty argument from the provided arguments.
 *
 * @param {...string} args - The arguments to check.
 * @returns {string|null} - The first non-empty argument, or null if all arguments are empty.
 */
export function firstNonEmpty(...args) {
   for (let arg of args) {
      if (arg && arg?.length > 0) {
         return arg;
      }
   }
   return null;
}

/**
 * Wraps the given content in triple backticks for code formatting.
 *
 * @param {string|Object} content - The content to wrap in triple backticks.
 * @param {string} [language=""] - The language identifier for syntax highlighting.
 * @returns {string} - The content wrapped in triple backticks.
 */
export function wrapTripleBackticks(content, language = "") {
   // Escape triple backticks
   content = typeof content === "string" ? content : JSON.stringify(content);
   if (content.includes("```")) {
      content = content.replace(/\\/g, "\\\\").replace(/```/g, "\\`\\`\\`");
   }
   return `\`\`\`${language}\n${content}\n\`\`\``;
}

/**
 * Wraps the given content in backticks for inline code formatting.
 *
 * @param {string} content - The content to wrap in backticks.
 * @returns {string} - The content wrapped in backticks.
 */
export function wrapBackticks(content) {
   return `\`${content}\``;
}

/**
 * Extracts JavaScript code blocks wrapped in triple backticks from the input string.
 *
 * @param {string} input - The input string containing code blocks.
 * @returns {string[]} - An array of JavaScript code blocks.
 */
export function extractJSTripleBackticks(input) {
   const regex = /```(?:js|javascript)\n?([\s\S]*?)```/g;
   let matches;
   const codes = [];
   while ((matches = regex.exec(input)) !== null) {
      codes.push(matches[1].trim());
   }
   return codes;
}

/**
 * Extracts code blocks wrapped in triple backticks from the input string.
 *
 * @param {string} input - The input string containing code blocks.
 * @returns {string[]} - An array of code blocks.
 */
export function extractTripleBackticks(input) {
   const matches = [...input.matchAll(/```(?:[^\n]*)\n([\s\S]*?)```/g)];
   return matches.map(match => match[1].trim());
}

/**
 * Generates an MD5 hash of the given string.
 *
 * @param {string} str - The string to hash.
 * @returns {string} - The MD5 hash of the string.
 */
export function md5(str) {
   return createHash("md5").update(str).digest("hex");
}

/**
 * Truncates the given string to the specified maximum length.
 *
 * @param {string} str - The string to truncate.
 * @param {number} maxLength - The maximum length of the truncated string.
 * @returns {string} - The truncated string with "..." appended if it exceeds the maximum length.
 */
export function truncateString(str, maxLength) {
   if (str?.length > maxLength) {
      return str.substring(0, maxLength) + "...";
   }
   return str;
}

/**
 * Removes the specified suffix from the given string.
 *
 * @param {string} str - The string to remove the suffix from.
 * @param {string} suffix - The suffix to remove.
 * @returns {string} - The string without the suffix.
 */
export function rmSuffix(str, suffix) {
   return str.endsWith(suffix) ? str.slice(0, -suffix.length) : str;
}

/**
 * Removes the specified prefix from the given string.
 *
 * @param {string} str - The string to remove the prefix from.
 * @param {string} prefix - The prefix to remove.
 * @returns {string} - The string without the prefix.
 */
export function rmPrefix(str, prefix) {
   return str.startsWith(prefix) ? str.slice(prefix.length) : str;
}

/**
 * Recursively removes the specified prefix from the given string.
 *
 * @param {string} str - The string to remove the prefix from.
 * @param {string} prefix - The prefix to remove.
 * @returns {string} - The string without the prefix.
 */
export function rmPrefixRecursively(str, prefix) {
   let s = "";
   while (s !== str && str.length > 0) {
      s = str;
      str = rmPrefix(str, prefix);
   }
   return str;
}

/**
 * Recursively removes the specified character from the beginning and end of the given string.
 *
 * @param {string} str - The string to remove the character from.
 * @param {string} char - The character to remove.
 * @returns {string} - The string without the character.
 */
export function stripRecursively(str, char) {
   let s = "";
   while (s !== str && str.length > 0) {
      s = str;
      str = rmSuffix(rmPrefix(str, char), char);
   }
   return str;
}

/**
 * Prefixes each line of the given string or array of strings with a line number.
 *
 * @param {string|Array<string>} lines - The string or array of strings to prefix.
 * @param {number} [offset=0] - The starting line number.
 * @returns {string} - The prefixed string.
 */
export function addLineNumbers(lines, offset = 0) {
   const list = typeof lines === "string" ? lines.split("\n") : lines;
   const result = [];
   for (let l = 0; l < list.length; l++) {
      result.push(`${l + offset}. ${list[l]}`);
   }
   return result.join("\n");
}

/**
 * Compares two strings case-insensitively.
 *
 * @param {string} a - The first string to compare.
 * @param {string} b - The second string to compare.
 * @returns {boolean} - True if the strings are equal, false otherwise.
 */
export function ciEquals(a, b) {
   if (typeof a !== "string" || typeof b !== "string") {
      return false;
   }
   return a.localeCompare(b, undefined, {sensitivity: "accent"}) === 0;
}

/**
 * Runs the given synchronous function with a specified timeout.
 *
 * @param {string} code - The synchronous function to run.
 * @param {number} timeout - The timeout duration in milliseconds.
 * @param {boolean} [expr=false] - If true, the code is evaluated as an expression.
 * @returns {*} - Result of the function
 * @throws {TimeoutError} - Throws an error if the function execution exceeds the timeout.
 */
export async function runAsyncWithTimeout(code, timeout, expr = false) {
   const cs = md5(code);

   function getPromise() {
      return new Promise(function (resolve, reject) {
         let src;
         if (expr) {
            src = `(async()=>{ 
            try {
               const r = ${code}; 
               tmpResolve_${cs}(r); 
            } catch(e) {
               tmpReject_${cs}(e);
            }
         
         })()`;
         } else {
            src = `(async()=>{ 
            try {
               ${code}; 
               tmpResolve_${cs}(); 
            } catch(e) {
               tmpReject_${cs}(e);
            }
         
         })()`;
         }

         global[`tmpResolve_${cs}`] = resolve;
         global[`tmpReject_${cs}`] = reject;

         const script = new vm.Script(src, {
            importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
         });
         script.runInThisContext({
            timeout,
            breakOnSigint: true,
         });
      });
   }

   const fnTimeout = ptimeout(getPromise, timeout);
   try {
      const res = await fnTimeout();
      delete global[`tmpResolve_${cs}`];
      delete global[`tmpReject_${cs}`];
      return res;
   } catch (e) {
      delete global[`tmpResolve_${cs}`];
      delete global[`tmpReject_${cs}`];
      throw e;
   }
}

/**
 * Runs the given synchronous function with a specified timeout.
 *
 * @param {Function} fn - The synchronous function to run.
 * @param {number} timeout - The timeout duration in milliseconds.
 * @returns {*} - Result of the function.
 * @throws {TimeoutError} - Throws an error if the function execution exceeds the timeout.
 */
export function runWithTimeoutDoSync(fn, timeout) {
   const script = new vm.Script('returnValue = functionToRun()');

   const context = vm.createContext();
   const wrappedFunction = (...arguments_) => {
      context.functionToRun = () => fn(...arguments_);
      script.runInNewContext(context, {timeout});
      return context.returnValue;
   };

   Object.defineProperty(wrappedFunction, 'name', {
      value: `functionTimeout(${fn.name || '<anonymous>'})`,
      configurable: true,
   });

   const s = process.hrtime();
   try {
      return wrappedFunction();
   } catch (e) {
      if (e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
         throw new TimeoutError(s);
      }
      throw e;
   }
}

/**
 * Checks if the given value is a number.
 *
 * @param {*} value - The value to check.
 * @returns {boolean} - True if the value is a number, false otherwise.
 */
export function isNumber(value) {
   return typeof value === "number";
}

/**
 * Checks if the given value is an object.
 *
 * @param {*} value - The value to check.
 * @returns {boolean} - True if the value is an object, false otherwise.
 */
export function isObject(value) {
   return typeof value === "object";
}

/**
 * Cleans a file system path by replacing all forward and backward slashes with underscores.
 *
 * @param {string} str - The file system path to clean.
 * @returns {string} - The cleaned file system path.
 */
export function cleanFs(str) {
   return str?.replace(/[\/\\]/g, "_");
}

/**
 * Joins access identifiers into a single string.
 * Each identifier is prefixed with a dot if it is a valid identifier,
 * otherwise it is wrapped in square brackets and JSON stringified.
 *
 * @param {...string} args - The access identifiers to join.
 * @returns {string} - The joined access identifiers as a single string.
 */
export function joinAccessIdentifiers(...args) {
   return rmPrefix(
      args
         .filter((x) => x?.length > 0)
         .map((n) => (isValidId(n) ? `.${n}` : `[${JSON.stringify(n)}]`))
         .join(""),
      ".",
   );
}

/**
 * Get a list of files in a ZIP file without extracting them.
 * @param {string} zipPath - The path to the ZIP file.
 * @returns {Promise<string[]>} - A promise that resolves to an array of file names in the ZIP.
 */
export function getZipFileList(zipPath) {
   return new Promise(async (resolve, reject) => {
      const fileNames = [];
      await yauzl.open(zipPath, {lazyEntries: true}, (err, zipFile) => {
         if (err) return reject(err);
         zipFile.readEntry();

         zipFile.on("entry", (entry) => {
            fileNames.push("/" + entry.fileName);
            zipFile.readEntry();
         });

         zipFile.on("end", () => {
            resolve(fileNames);
         });

         zipFile.on("error", (err) => {
            reject(err);
         });
      });
   });
}

/**
 * Recursively lists all files and/or directories in a directory that match a pattern.
 *
 * @param {string} directory - The directory to search within.
 * @param {RegExp|undefined} pattern - The regular expression pattern to match files or directories against.
 * @param {"filesOnly" | "dirOnly" | "both"} type - The type of results to return.
 * @returns {string[]} - An array of absolute file or directory paths that match the pattern.
 */
export function recListFiles(directory, pattern = undefined, type = "filesOnly") {
   const files = readdirSync(directory);
   const result = [];

   for (const file of files) {
      const fullPath = join(directory, file);
      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
         if (file === "node_modules") {
            continue;
         }
         if ((type === "dirOnly" || type === "both") && (!pattern || pattern.test(file))) {
            result.push(fullPath);
         }
         result.push(...recListFiles(fullPath, pattern, type));
      } else if (stat.isFile() && (type === "filesOnly" || type === "both") && (!pattern || pattern.test(file))) {
         result.push(fullPath);
      }
   }
   return result;
}

/**
 * Extracts a portion of the source code based on the provided location range.
 *
 * @param {LocationRange} location - The range of the source code to extract.
 * @param {string} fileContent - The content of the file from which to extract the source code.
 * @returns {string} - The extracted source code.
 * @throws {Error} - Throws an error if the location range is invalid.
 */
export function extractSourceCode(location, fileContent) {
   const {startLine, startColumn, endLine, endColumn} = location;
   const lines = fileContent.split("\n");
   if (startLine < 1 || endLine > lines.length || startLine > endLine) {
      throw new Error(`Invalid location: ${JSON.stringify(location)}`);
   }
   const extractedLines = [];
   for (let i = startLine - 1; i <= endLine - 1; i++) {
      const line = lines[i];
      if (i === startLine - 1 && i === endLine - 1) {
         extractedLines.push(line.substring(startColumn, endColumn));
      } else if (i === startLine - 1) {
         extractedLines.push(line.substring(startColumn));
      } else if (i === endLine - 1) {
         extractedLines.push(line.substring(0, endColumn));
      } else {
         extractedLines.push(line);
      }
   }
   return extractedLines.join("\n");
}

/**
 * Indents each line of the given string by the specified number of spaces.
 *
 * @param {string} str - The string to indent.
 * @param {number} spaces - The number of spaces to indent each line.
 * @returns {string} - The indented string.
 */
export function indent(str, spaces) {
   return str
      .split("\n")
      .map((line) => " ".repeat(spaces) + line)
      .join("\n");
}

/**
 * Wraps the given exploit code in an asynchronous function.
 *
 * @param {string} exploit - The exploit code to wrap.
 * @returns {string} - The wrapped exploit code.
 */
export function wrapInExploitFunction(exploit) {
   return `async function exploit() {\n${indent(exploit, 3)}\n}\nawait exploit();`;
}

/**
 * Checks if the given file path is a directory.
 *
 * @param filePath {string} - The file path to check.
 * @returns {boolean} - True if the file path is a directory, false otherwise.
 */
export function isDirectory(filePath) {
   try {
      return statSync(filePath).isDirectory();
   } catch (error) {
      return false;
   }
}

/**
 * Parses the given CVE identifier and returns the year part.
 *
 * @param cve {string} - The CVE identifier to parse.
 * @returns {number} - The year part of the CVE identifier.
 */
export function getCveYear(cve) {
   return Number(cve.split("-")[1]);
}

/**
 * Return a file path that is available in the file system.
 *
 * @param filePath {string} - The file path to check.
 * @returns {string} - The available file path.
 */
export function getAvailableFilePath(filePath) {
   if (!existsSync(filePath)) {
      return filePath;
   }

   const dir = dirname(filePath);
   const ext = extname(filePath);
   const baseName = basename(filePath, ext);

   let counter = 1;
   let newPath = '';

   do {
      newPath = join(dir, `${baseName}_${counter}${ext}`);
      counter++;
   } while (existsSync(newPath));

   return newPath;
}

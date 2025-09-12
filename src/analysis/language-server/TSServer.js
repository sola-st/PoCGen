import {spawn} from "child_process";
import * as readline from "node:readline";
import {OutputHandlerRegistry} from "./outputHandlerRegistry.js";
import {TSServerOutputHandler, TSServerRequest} from "./TSServerRequest.js";
import {TSServerResponse} from "./TSServerResponse.js";
import {TSServerProcessException, TSServerStopLoopException,} from "./TSServerExceptions.js";
import LocationRange from "../../models/locationRange.js";
import {existsSync} from "node:fs";
import {join} from "path";

/**
 * @typedef {import("../../models/locationRange").default} LocationRange
 */

/**
 * @type {string}
 */
const CONTENT_LENGTH_HEADER = "Content-Length: ";

export const TS_SERVER_BINARY = "tsserver";

// https://github.com/microsoft/TypeScript/wiki/Standalone-Server-(tsserver)
export class TSServer {
   constructor(srcRoot) {
      this.tsServerProc = spawn(TS_SERVER_BINARY, {
         stdio: ["pipe", "pipe", "pipe"],
      });
      this.tsServerProc.on("error", (err) => {
         console.error(err);
      });
      this.tsServerProc.on("exit", (code) => {
         if (!this.sentSigKill)
            console.error(`TS Server exited with code ${code}`);
      });
      this.srcRoot = srcRoot;
      this.projectFiles = [];
      this.seq = 0;
      this.outputHandlerRegistry = new OutputHandlerRegistry();
      this.tasks = {
         watchingResponse: this.monitorOutput(),
      };
      this.sentSigKill = false;
   }

   /**
    * @param cmd
    * @param expectOutput
    * @param args
    * @returns {Promise<{request: TSServerRequest, outputHandler: TSServerOutputHandler|null}>}
    */
   async sendRequest(cmd, expectOutput, args = null) {
      const request = new TSServerRequest(this.seq++, cmd, args);
      console.debug(`Sending Request: ${request}`);
      let outputHandler = null;
      if (expectOutput) {
         outputHandler = new TSServerOutputHandler(request.seq);
         this.outputHandlerRegistry.registerHandler(expectOutput, outputHandler);
      }
      this.tsServerProc.stdin.write(request.toBytes());
      return {request, outputHandler};
   }

   /**
    * @param {string} absolutePath
    * @returns {Promise<void>}
    */
   async cmdOpen(absolutePath) {
      const openRequest = {
         file: absolutePath,
      };
      await this.sendRequest("open", null, openRequest);
   }

   async monitorOutput() {
      try {
         let bodyLength = 0;
         const rl = readline.createInterface({
            input: this.tsServerProc.stdout,
            output: this.tsServerProc.stdin,
            terminal: false,
         });
         for await (const chunk of rl) {
            const line = chunk.toString().trim();
            if (line === "") {
               continue;
            }
            console.debug("<< " + line);
            if (bodyLength === 0 && line.startsWith(CONTENT_LENGTH_HEADER)) {
               bodyLength = parseInt(line.slice(CONTENT_LENGTH_HEADER.length), 10);
            } else if (bodyLength > 0) {
               const body = chunk.toString().slice(0, bodyLength);
               bodyLength = 0;

               const outputBody = TSServerResponse.fromBytes(Buffer.from(body));
               if (outputBody) {
                  await this.outputHandlerRegistry.onOutput(outputBody);
               }
            }
         }
      } catch (error) {
         if (
            error instanceof TSServerStopLoopException ||
            error instanceof TSServerProcessException
         ) {
            return;
         }
         console.error(error);
      }
   }

   async stop() {
      this.sentSigKill = true;
      await this.sendRequest("exit", null);
      console.log(`Killed ${this.tsServerProc.pid}`);
   }

   getLocationFromRef(ref) {
      if (ref.contextStart) {
         return new LocationRange(
            ref.file,
            //relative(this.srcRoot, ref.file),
            ref.contextStart.line,
            ref.contextStart.offset - 1,
            ref.contextEnd.line,
            ref.contextEnd.offset - 1,
         );
      }
      return new LocationRange(
         ref.file,
         // relative(this.srcRoot, ref.file),
         ref.start.line,
         ref.start.offset - 1,
         ref.end.line,
         ref.end.offset - 1,
      );
   }

   /**
    * @param {LocationRange} location
    * @returns {Promise<LocationRange[]>}
    */
   async getReferences(location) {
      const response = await this.#cmd("references", location);
      /**
       * @type {LocationRange[]}
       */
      const locations = [];
      for (const ref of response.body?.refs ?? []) {
         const refLocation = this.getLocationFromRef(ref);
         if (refLocation.contains(location)) {
            continue;
         }
         locations.push(refLocation);
      }
      // Sort locations by file path:startLine:startColumn
      locations.sort((a, b) => `${a.filePath}:${a.startLine}:${a.startColumn}`.localeCompare(`${b.filePath}:${b.startLine}:${b.startColumn}`));
      return locations;
   }

   /**
    * @param {LocationRange} location
    * @returns {Promise<LocationRange[]>}
    */
   async getDefinitions(location) {
      const response = await this.#cmd("definition", location);
      /**
       * @type {LocationRange[]}
       */
      const locations = [];
      for (const ref of response.body ?? []) {
         locations.push(this.getLocationFromRef(ref));
      }
      locations.sort((a, b) => `${a.filePath}:${a.startLine}:${a.startColumn}`.localeCompare(`${b.filePath}:${b.startLine}:${b.startColumn}`));
      return locations;
   }

   /**
    * @param {string} command
    * @param {LocationRange} location
    * @returns {Promise<*[]>}
    */
   async #cmd(command, location) {
      if (this.sentSigKill) {
         throw new Error("TS Server is stopped");
      }
      const absPath = join(this.srcRoot, location.filePath);
      if (!this.projectFiles.includes(absPath)) {
         // Check whether file exists
         if (!existsSync(absPath)) {
            throw new Error(`File ${absPath} does not exist`);
         }
         await this.cmdOpen(absPath);
         this.projectFiles.push(absPath);
      }
      const newLoc = LocationRange.toLanguageServer(location);
      const args = {
         file: absPath,
         line: newLoc.startLine,
         offset: newLoc.startColumn,
      };
      const {outputHandler} = await this.sendRequest(command, "response", args);
      const response = await outputHandler.waitOutput();
      if (response.success === false) {
         console.error(response.message ?? `Error executing command: ${command}`);
      }
      return response;
   }

   async init(options = {}) {
      const args = {
         hostInfo: "tsserver-client-node",
         preferences: {
            providePrefixAndSuffixTextForRename: true,
            allowRenameOfImportPath: true,
            includePackageJsonAutoImports: "auto",
            excludeLibrarySymbolsInNavTo: true,
         },
         watchOptions: {},
         ...options,
      };
      const {outputHandler} = await this.sendRequest(
         "configure",
         "response",
         args,
      );
      const response = await outputHandler.waitOutput();
      return response.success;
   }
}

import {esc, rmPrefix, rmPrefixRecursively, runAsyncWithTimeout, sleep, TimeoutError} from "../../../utils/utils.js";
import getStacktrace from "../../../utils/stacktraceUtils.js";
import inspector from "inspector";
import RuntimeInfo from "../../../models/runtimeInfo.js";
import {containsPoint} from "../../../models/locationRange.js";
import {join} from "path";
import HitBreakpoint from "../../../models/hitBreakpoint.js";
import * as stackTraceParser from "stacktrace-parser";

/**
 * @typedef {Object} BreakPoint
 * @property {string} breakpointId - The breakpoint id.
 * @property {BreakpointRequest[]} requests - The expressions to evaluate.
 * @type {Array.<BreakPoint>}
 */

/**
 * @typedef {import("../../../models/source").default} Source - Represents the vulnerable function.
 * @typedef {import("../../../models/hitBreakpoint").default} HitBreakpoint - Represents a breakpoint that has been hit.
 * @typedef {import("../../../models/runtimeInfo").default} RuntimeInfo - Represents runtime information.
 * @typedef {import("../../../models/locationRange").default} LocationRange - Represents a range of locations in the source code.
 * @typedef {import("../../../models/breakpointRequest").default} BreakpointRequest - Represents a request to set a breakpoint.
 */

/**
 * @typedef {Object} ValidatorConfig - Configuration options for the verifier.
 * @property {Source} source - The source object.
 * @property {string} nmPath - The node modules path.
 * @property {string} nmModulePath - The specific module path.
 * @property {BreakpointRequest[]} debugRequests - Debugging breakpoint requests.
 * @property {string} exploit - The exploit code.
 * @property {string} vulnerabilityTypeLabel - The label for the vulnerability type.
 * @property {string} baseDir - The base directory.
 */

/**
 * @type {{SERVER: string, CHILD_PROCESS: string, SOCKET: string, WRITE_STREAM: string}}
 */
export const HANDLES = {
   CHILD_PROCESS: "ChildProcess",
   WRITE_STREAM: "WriteStream",
   SOCKET: "Socket",
   SERVER: "Server",
};

export const MessageType = {
   VERIFY: "eval",
   DEBUG: "debug",
   RESULT: "run-result",
};

export const EXPLOIT_TIMEOUT_DURATION = 1000 * 60; // 1 minute

/**
 * Class representing a verifier for debugging and runtime analysis.
 *
 * @typedef {import("inspector").Session} Session - Represents a debugging session.
 */
export class Validator {

   /**
    * @type {ValidatorConfig}
    */
   config;

   /**
    * @type {RuntimeInfo}
    */
   runtimeInfo;

   /**
    * @type {Session}
    */
   session;

   /**
    * Set up the verifier with configuration options.
    *
    * @param {ValidatorConfig} config - Configuration options for the verifier.
    * @returns {Promise<void>}
    */
   async setup(config) {
      this.config = config;
      this.runtimeInfo = new RuntimeInfo();
      await this.initDebugger();
   }

   async initDebugger() {
      const session = new inspector.Session();
      session.connect();
      this.session = session;

      await this.session.post("Debugger.enable", (err, _) => {
         if (err) {
            this.log(err);
         }
      });
      await this.session.post("Debugger.setAsyncCallStackDepth", {
         maxDepth: 32,
      });
      await this.session.post("Profiler.enable", (err) => {
         if (err) {
            this.log(err);
         }
      });
      await this.session.post("Profiler.startPreciseCoverage", {
         detailed: true,
      });
   }

   /**
    * Set up the verifier with configuration options and debugging.
    * @param {BreakpointRequest[]} breakpointRequests - Debugging breakpoint requests.
    */
   async addBreakpoints(breakpointRequests) {
      const session = this.session;

      /**
       * @type {BreakPoint[]}
       */
      const breakpoints = [];

      for (const breakpointRequest of breakpointRequests) {
         const existingBreakpoint = breakpoints.find((bp) => bp.requests.some((req) =>
            req.location.filePath === breakpointRequest.location.filePath &&
            req.location.startLine === breakpointRequest.location.startLine));
         if (existingBreakpoint) {
            existingBreakpoint.requests.push(breakpointRequest);
            continue;
         }
         const url = `file://${join(this.config.nmPath, breakpointRequest.location.filePath)}`;
         await session.post("Debugger.setBreakpointByUrl", {
            lineNumber: breakpointRequest.location.startLine,
            url,
         }, (err, result) => {
            if (err) {
               this.log(err);
            } else {
               this.log(`Breakpoint set: ${result.breakpointId}`);
               breakpoints.push({
                  breakpointId: result.breakpointId,
                  requests: [breakpointRequest],
               })
            }
         });
      }

      const hitBreakpointIds = [];

      session.on("Debugger.paused", async (event) => {
         try {
            const hitBreakpointId = event.params?.hitBreakpoints[0];
            if (!this.isCallFromSource()) {
               this.log(`!fromSource Breakpoint hit: ${hitBreakpointId}`);
               return;
            }
            if (hitBreakpointIds.includes(hitBreakpointId)) {
               return;
            }
            hitBreakpointIds.push(hitBreakpointId);
            const bpRequest = breakpoints.find((bp) => bp.breakpointId === hitBreakpointId);
            // Check whether already hit.
            if (this.runtimeInfo.hitBreakpoints.some((bp) => bp.breakpointId === hitBreakpointId)) {
               return;
            }
            if (bpRequest) {
               this.log(`Breakpoint hit: ${hitBreakpointId}`);

               // Evaluate the expression
               for (const request of bpRequest.requests) {
                  await session.post("Debugger.evaluateOnCallFrame", {
                     callFrameId: event.params.callFrames[0].callFrameId,
                     expression: `JSON.stringify(${request.expression})`,
                     generatePreview: false,
                  }, async (err, data) => {
                     if (err) {
                        this.log(err);
                        return;
                     }
                     if (data.result.subtype === "error") {
                        this.log(`${data.result.className}: ${request.expression}`);
                        return;
                     }
                     this.runtimeInfo.hitBreakpoints.push(new HitBreakpoint(request, data.result));
                  });
               }
            } else {
               this.log(`Breakpoint ${hitBreakpointId} not found in map`);
            }
         } finally {
            await session.post("Debugger.resume");
         }
      });

   }

   /**
    * Perform a check on the provided exploit code.
    *
    * @param {string} exploitCode - The code to be checked for exploits.
    * @returns {Promise<void>}
    */
   async verifyExploit(exploitCode) {
      try {
         await runAsyncWithTimeout(exploitCode, EXPLOIT_TIMEOUT_DURATION);
      } catch (error) {
         if (error instanceof TimeoutError) {
            this.log("Exploit timed out");
            this.runtimeInfo.refineMessages.push("Exploit timed out");
         } else {
            this.reportError(error);
         }
      }
   }

   /**
    * Check whether the verifier has confirmed the exploit.
    *
    * @returns {Promise<boolean>}
    */
   async check() {
      return (await this.getRuntimeInfo()).confirmedFromSource;
   }

   /**
    * Report an error by logging it and adding it to the runtime information.
    *
    * @param {Error|string} e - The error to report. Can be an Error object or a string.
    */
   reportError(e) {
      if (!e) {
         return;
      }
      if (e instanceof Error && e.stack) {
         const stackFrames = stackTraceParser.parse(e.stack);
         this.log(`Error: ${esc(e.stack)}`);
         this.runtimeInfo.errors.push({message: e.message, stackFrames, stack: e.stack});
      } else {
         let error = e;
         if (typeof e !== "string") {
            error = JSON.stringify(e);
         }
         this.log(`Error: ${esc(error)}`);
         this.runtimeInfo.errors.push(error);
      }
   }

   /**
    * Get the runtime information.
    *
    * @returns {Promise<RuntimeInfo>}
    */
   async getRuntimeInfo() {
      await this.waitActiveHandles();

      const errors = [];
      if (this.runtimeInfo.errors?.length > 0) {
         for (const error of this.runtimeInfo.errors) {
            if (!error.stackFrames) {
               errors.push(error);
               continue;
            }
            const filteredStackFrames = error.stackFrames.map((frame) => {
                  if (frame.file.startsWith("file://") || frame.file.startsWith("/")) {
                     const filePath = rmPrefix(frame.file, "file://");
                     if (filePath.startsWith(this.config.nmPath)) {
                        return {
                           ...frame,
                           file: rmPrefix(rmPrefix(filePath, this.config.nmPath), "/"),
                        };
                     }
                     return frame;
                  } else if (frame.file.startsWith("node:")) {
                     return frame;
                  }
                  return null;
               }
            ).filter((frame) => frame !== null);

            const pat = "at exploit (evalmachine.<anonymous>"

            const lines = error.stack?.split("\n");

            // Filter out frames that are not related to the target library.
            let stack;
            if (lines) {
               stack = "";
               for (const line of lines) {
                  if (line.includes(pat)) {
                     break;
                  }
                  stack += line + "\n";
               }
               stack = stack.replaceAll(this.config.nmPath, ".").trim();
            }
            errors.push({
               message: error.message,
               stack,
               stackFrames: filteredStackFrames,
            })
         }
      }
      return {
         confirmed: this.runtimeInfo.confirmed,
         confirmedFromSource: this.runtimeInfo.confirmedFromSource,
         refineMessages: this.runtimeInfo.refineMessages,
         errors,
         hitBreakpoints: this.runtimeInfo.hitBreakpoints,
      };
   }

   /**
    * Check whether the call originates from the source.
    *
    * @returns {boolean}
    */
   isCallFromSource() {
      const sourceFileName = this.config.source.callable.location.filePath;
      const messages = [];
      messages.push(`source: ${JSON.stringify(this.config.source.callable.location)}`);
      if (sourceFileName) {
         for (const trace of getStacktrace()) {
            if (!trace.getFileName()) continue;
            const traceFileName = rmPrefixRecursively(
               rmPrefix(rmPrefix(trace.getFileName(), "file://"), this.config.nmPath),
               "/",
            );
            messages.push(
               `trace: ${traceFileName}:${trace.getLineNumber()}:${trace.getColumnNumber()}`,
            );
            if (
               sourceFileName === traceFileName &&
               containsPoint(
                  this.config.source.callable.location,
                  trace.getLineNumber(),
                  trace.getColumnNumber(),
               )
            ) {
               return true;
            }
         }
      }
      // Check async
      let asyncStackTraceObject;
      this.session.on("Debugger.paused", (pausedEvent) => {
         asyncStackTraceObject = pausedEvent.params?.asyncStackTrace;
      });
      this.session.post("Debugger.pause");
      if (asyncStackTraceObject) {
         const callFrames = [];
         callFrames.push(...asyncStackTraceObject.callFrames);
         while (asyncStackTraceObject.parent) {
            asyncStackTraceObject = asyncStackTraceObject.parent;
            callFrames.push(...asyncStackTraceObject.callFrames);
         }
         for (const callFrame of callFrames) {
            const traceFileName = rmPrefixRecursively(
               rmPrefix(rmPrefix(callFrame.url, "file://"), this.config.nmPath),
               "/",
            );
            if (!traceFileName) continue;
            messages.push(
               `async: ${traceFileName}:${callFrame.lineNumber}:${callFrame.columnNumber}`,
            );
            if (
               traceFileName === sourceFileName &&
               containsPoint(
                  this.config.source.callable.location,
                  callFrame.lineNumber + 1, // Make line numbers 1-based (https://chromedevtools.github.io/devtools-protocol/v8/Runtime/#type-CallFrame)
                  callFrame.columnNumber,
               )
            ) {
               return true;
            }
         }
      }
      this.log("!fromSource:");
      for (const message of messages) {
         this.log(message);
      }
      return false;
   }

   log(...args) {
      args[0] = `[Verifier] ` + args[0];
      console.log(...args);
   }

   /**
    * Waits for active handles to close, optionally filtering by handle type.
    *
    * @param {string|undefined} filterType - Handle type to filter by.
    * @param {number} rounds - Wait up to 10 seconds by default if filterType is not provided.
    * @returns {Promise<void>}
    * @see HANDLES
    */
   async waitActiveHandles(filterType = undefined, rounds = 10) {
      let handles;
      let curDelay = 10;
      let ctr = 0;
      let prevHandles;
      while (ctr++ < rounds && !this.runtimeInfo.confirmedFromSource) {
         this.log(`Handles:${ctr} Checking open handles...`);
         handles = [];
         process._getActiveHandles().forEach(function (h) {
            if (!h) {
               return;
            }
            if (filterType && h.constructor.name !== filterType) {
               return;
            }
            switch (h.constructor.name) {
               case HANDLES.CHILD_PROCESS:
                  handles.push(
                     `process: pid=${h.pid ?? "?"}, arg=${JSON.stringify(h.spawnargs)}`,
                  );
                  break;
               case HANDLES.WRITE_STREAM:
                  if (h.fd > 2) {
                     handles.push(
                        `write stream: fd=${h.fd ?? "?"}, path=${h._type ?? "?"}`,
                     );
                  }
                  break;
               case HANDLES.SOCKET:
                  handles.push(`socket: fd=${h._handle?.fd ?? "?"}`);
                  break;
               case HANDLES.SERVER:
                  handles.push(
                     `server: fd=${h._handle?.fd ?? "?"}, connection: ${h._connectionKey ?? "?"}`,
                  );
                  break;
               case "Pipe":
                  break;
               default:
                  break;
            }
         });
         if (filterType && handles.length === 0) {
            return;
         }
         for (const h of handles) {
            this.log(`Handles:${ctr} ${h}`);
         }
         await sleep(Math.min(curDelay, 60_000));
         curDelay *= 2;
         prevHandles = handles;
      }
      this.log(`Handles:${ctr} Done`);
   }

}

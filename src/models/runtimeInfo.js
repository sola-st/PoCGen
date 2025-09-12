/**
 * @typedef {import("../../node_modules/stacktrace-parser/dist/stack-trace-parser.js").StackFrame} StackFrame
 */

/**
 * @typedef {Object} ErrorDetails
 * @property {string} message - A descriptive error message.
 * @property {string} stack - The error stack trace.
 * @property {StackFrame[]} stackFrames - An array of stack frames representing the error stack trace.
 */

/**
 * Class storing runtime information.
 */
export default class RuntimeInfo {
   /**
    * List of messages to refine.
    * @type {string[]}
    */
   refineMessages = [];

   /**
    * Indicates if the goal was met.
    * If this is true and {@link confirmedFromSource} is false, the exploit is a possible false positive and needs to be triaged.
    * @type {boolean}
    */
   confirmed = false;

   /**
    * True if dynamic analysis shows that the oracle-relevant action was executed from the source function.
    * @type {boolean}
    */
   confirmedFromSource = false;

   /**
    * List of error messages.
    * @type {Array<ErrorDetails|String>}
    */
   errors = [];

   /**
    * List of coverage information.
    * @type {CoverageInfo[]}
    */
   coverageInfoList = [];

   /**
    * List of hit breakpoints.
    * @type {HitBreakpoint[]}
    */
   hitBreakpoints = [];

   /**
    * List of console messages.
    * Each message is an object containing a message string and a boolean indicating if it is stderr.
    * @type {Array<{message: string, stderr: boolean}>}
    */
   consoleMessages = [];
}

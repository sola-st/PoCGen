/**
 * Retrieves the current stack trace.
 *
 * @param {Function|undefined} belowFn - The function to exclude from the stack trace. If undefined, the current function is excluded.
 * @returns {CallSite[]} An array of CallSite objects representing the stack trace.
 */
export default function getStacktrace(belowFn = undefined) {
   const originalStackTraceLimit = Error.stackTraceLimit;
   const originalPrepareStackTrace = Error.prepareStackTrace;

   Error.stackTraceLimit = Infinity;
   const tmp = {};
   Error.prepareStackTrace = function (dummyObject, v8StackTrace) {
      return v8StackTrace;
   };
   Error.captureStackTrace(tmp, belowFn || getStacktrace);

   const v8StackTrace = tmp.stack;
   Error.prepareStackTrace = originalPrepareStackTrace;
   Error.stackTraceLimit = originalStackTraceLimit;
   return v8StackTrace;
}

function CallSite(properties) {
   for (const property in properties) {
      this[property] = properties[property];
   }
}

[
   "this",
   "typeName",
   "functionName",
   "methodName",
   "fileName",
   "lineNumber",
   "columnNumber",
   "function",
   "evalOrigin",
].forEach(function (property) {
   CallSite.prototype[property] = null;
   CallSite.prototype["get" + property[0].toUpperCase() + property.substr(1)] =
      function () {
         return this[property];
      };
});

[
   'topLevel',
   'eval',
   'native',
   'constructor'
].forEach(function (property) {
   CallSite.prototype[property] = false;
   CallSite.prototype['is' + property[0].toUpperCase() + property.substring(1)] = function () {
      return this[property];
   }
});

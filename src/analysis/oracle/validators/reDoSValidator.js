import {EXPLOIT_TIMEOUT_DURATION, Validator} from "./validator.js";
import {firstNonEmpty, runAsyncWithTimeout, runWithTimeoutDoSync, TimeoutError} from "../../../utils/utils.js";

const _exec = RegExp.prototype.exec;

export const backtrackingLimit = 30_000;
export const durationMs = 1_500;

/**
 * Requires a patched node.js version to detect excessive backtracking.
 * https://github.com/v8/v8/blob/refs/tags/13.3.364/src/regexp/regexp.cc#L852
 */
export default class ReDoSValidator extends Validator {

   /** @inheritDoc */
   async verifyExploit(exploitCode) {
      try {
         if (typeof exploitCode === "function") {
            await exploitCode();
         }
         await runAsyncWithTimeout(exploitCode, EXPLOIT_TIMEOUT_DURATION);
      } catch (error) {
         this.runtimeInfo.confirmed = this.runtimeInfo.confirmed || this.isSuccessError(error);
         if (!(error instanceof TimeoutError)) {
            this.reportError(error);
         }
      }
   }

   /** @inheritDoc */
   async setup(config) {
      await super.setup(config);
      this.hook();
   }

   hook() {
      const self = this;
      RegExp.prototype.exec = function (...args) {
         if (self.runtimeInfo.confirmedFromSource) {
            return null;
         }
         try {
            return runWithTimeoutDoSync(() => {
               return _exec.apply(this, args);
            }, durationMs);
         } catch (e) {
            if (self.isSuccessError(e)) {
               const callFromSource = self.isCallFromSource();
               self.runtimeInfo.confirmed = true;
               if (callFromSource) {
                  self.log(`Confirmed (${firstNonEmpty(e.message, e.name, e)}): vulnerable regex: ${this.toString()}`);
                  self.runtimeInfo.confirmedFromSource = true;
               } else {
                  self.log(`Confirmed !fromSource (${firstNonEmpty(e.message, e.name, e)}): ${this.source}`);
               }
            }
            return null;
         }
      };
      for (const propName of [/*"replace", "match", "split", "search"*/]) {
         const originalMethod = String.prototype[propName];
         String.prototype[propName] = function () {
            if (self.runtimeInfo.confirmedFromSource) {
               return originalMethod.apply(this, arguments);
            }
            try {
               return runWithTimeoutDoSync(() => {
                  return originalMethod.apply(this, arguments);
               }, durationMs);
            } catch (e) {
               if (self.isSuccessError(e)) {
                  self.runtimeInfo.confirmed = true;
                  const callFromSource = self.isCallFromSource();
                  if (callFromSource) {
                     self.log(`Confirmed (${firstNonEmpty(e.message, e.name, e)}): ${propName}(${arguments[0]?.toString()})`);
                     self.runtimeInfo.confirmedFromSource = true;
                  } else {
                     self.log(`Confirmed !fromSource (${firstNonEmpty(e.message, e.name, e)}): ${propName}(${arguments[0]?.toString()})`);
                  }
               }
               return null;
            }
         };
      }
   }

   /**
    * Checks if the given error is considered a success error.
    * @param {Error|string} e - The error to check.
    * @returns {boolean} - Returns true if the error is "illegal access" or an instance of TimeoutError.
    */
   isSuccessError(e) {
      return e === "illegal access" || e instanceof TimeoutError;
   }

}

export const name = "Regular Expression Denial of Service (ReDoS)";
export const label = "redos";
export const cwe = [1333, 730, 400];
export const goal = `exceed the backtracking limit of ${backtrackingLimit}`;
export const validator = ReDoSValidator;
export const nodeArgv = [
   "--enable-experimental-regexp-engine-on-excessive-backtracks",
   `--regexp-backtracks-before-fallback=${backtrackingLimit}`];

export async function validate(asyncFn) {
   const start = process.hrtime();
   try {
      await asyncFn();
      const end = process.hrtime(start);
      return end[0] * 1_000 + end[1] / 1_000_000 > 1500;
   } catch (e) {
      return e === "illegal access";
   }
}

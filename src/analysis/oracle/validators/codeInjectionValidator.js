import {Validator} from "./validator.js";
import {esc, wrapBackticks, wrapTripleBackticks} from "../../../utils/utils.js";

const _eval = global.eval;
const _Function = Function;

export const winFunction = "process.seteuid(42)";

export default class CodeInjectionValidator extends Validator {

   /**
    * @type {Array<{code: string, error: Error}>}
    */
   evalStatements = [];

   /**
    * @type {Array<{code: string, error: Error}>}
    */
   functionConstructorInvocations = [];

   /** @inheritDoc */
   async setup(config) {
      await super.setup(config);

      this.evalStatements = [];
      this.functionConstructorInvocations = [];

      const winLogic = () => {
         this.runtimeInfo.confirmed = true;
         const calledFromSource = this.isCallFromSource();
         if (calledFromSource) {
            this.log("Confirmed");
            this.runtimeInfo.confirmedFromSource = true;
         } else {
            this.log(`!fromSource`);
            this.runtimeInfo.refineMessages.push(
               `the exploit executed ${winFunction} but not through making use of the code injection vulnerability`,
            );
         }
      };
      const _seteuid = process.seteuid;
      process.seteuid = (uid) => {
         if (uid == 42) {
            winLogic();
         }
         _seteuid(uid);
      };
      this.setupRefinement();
   }

   setupRefinement() {
      const self = this;

      /*global.eval_ = function (code) {
         let result, evalError;
         try {
            result = _eval(code);
         } catch (e) {
            console.error(e);
            evalError = e;
         }
         if (!self.runtimeInfo.confirmedFromSource && self.isCallFromSource()) {
            self.log(`evaluating code: ${esc(code)}`);
            self.evalStatements.push({code: code, error: evalError});
         }
         return result;
      };*/

      global.Function = new Proxy(_Function, {
         construct(target, argArray, newTarget) {
            if (target !== _Function) {
               return Reflect.construct(target, argArray, newTarget);
            }
            let execError, execResult;
            try {
               execResult = Reflect.construct(target, argArray, newTarget);
            } catch (e) {
               execError = e;
            }
            const code = argArray[argArray.length - 1];
            if (!self.runtimeInfo.confirmedFromSource && self.isCallFromSource()) {
               self.log(`executing code: ${esc(code)}`);
               self.functionConstructorInvocations.push({code: code, error: execError});
            }
            if (execError) {
               throw execError;
            }
            return execResult;
         }
      });
   }

   /** @inheritDoc */
   async getRuntimeInfo() {
      const runtimeInfo = await super.getRuntimeInfo();
      if (this.evalStatements?.length > 0) {
         let prompt = ``;
         prompt += `The exploit reached the eval sink and executed the code:\n`;
         for (const {code, error} of this.evalStatements) {
            prompt += wrapTripleBackticks(code, "js");
            if (error) {
               prompt += `\nError:\n${wrapTripleBackticks(error.stack)}`;
            }
            prompt += `\n`;
         }
         prompt += `However, the exploit did not execute ${winFunction}.`;
         runtimeInfo.refineMessages.push(prompt);
      }
      if (this.functionConstructorInvocations?.length > 0) {
         let prompt = ``;
         prompt += `The exploit reached the Function constructor with the following code:\n`;
         for (const {code, error} of this.functionConstructorInvocations) {
            prompt += wrapTripleBackticks(code, "js");
            if (error) {
               prompt += `\nError:\n${wrapTripleBackticks(error.stack)}`;
            }
            prompt += `\n`;
         }
         prompt += `However, the exploit did not execute ${winFunction}.`;
         runtimeInfo.refineMessages.push(prompt);
      }
      return runtimeInfo;
   }
}

export const name = "Code Injection (eval, Function)";
export const label = "code-injection"
export const cwe = [94, 95, 96, 97, 98, 99];
export const goal = `execute ${wrapBackticks(winFunction)}`;
export const validator = CodeInjectionValidator;

export async function validate(asyncFn) {
   let success = false;
   process.seteuid = (uid) => {
      if (uid == 42) {
         success = true;
      }
   };
   try {
      await asyncFn();
   } catch (e) {
      console.error(e);
   }
   return success;
}

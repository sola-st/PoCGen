import {existsSync} from "node:fs";
import {Validator} from "./validator.js";
import {exec} from "child_process";
import {basename} from "node:path";
import {esc, wrapBackticks, wrapTripleBackticks} from "../../../utils/utils.js";

const rceBinary = "/usr/bin/genpoc";
export const rceWritePath = "/.executed";

/**
 * @typedef {Object} ExecutedProcess
 * @property {boolean} fromSource
 * @property {string[]} args
 * @property {string} cwd
 * @property {string} signalCode
 */

export default class CommandInjectionValidator extends Validator {

   /**
    * @type {ExecutedProcess[]}
    */
   executedCommands = [];

   constructor() {
      super();
      this.ChildProcessInstance = exec("id");
      this.spawn_sync = process.binding("spawn_sync");
      this._spawn = this.spawn_sync.spawn;
      this.ChildProcess_spawn = this.ChildProcessInstance.__proto__.spawn;
   }

   /** @inheritDoc */
   async setup(config) {
      await super.setup(config);
      this.hookChildProcess();
      this.hookSpawn();
      this.executedCommands = [];
   }

   hookChildProcess() {
      const self = this;
      this.ChildProcessInstance.__proto__.spawn = function (options) {
         if (self.runtimeInfo.confirmedFromSource) {
            return self.ChildProcess_spawn.call(this, options);
         }
         // Disable stdin to prevent blocking
         options.stdio = ["ignore", "pipe", "pipe"];
         const calledFromSource = self.isCallFromSource();
         // The verification process is a bit harder due to the call being async
         // If we want to avoid race conditions we could try running the command in a synchronous manner, but this might have side effects
         // For now: pre-check here & post-check in `onexit`, observe whether any issues arise
         self.cleanup();
         if (self.checkCondition()) {
            self.log("setup failed");
            return self.ChildProcess_spawn.call(this, options);
         }
         // Hook the onexit function
         // https://github.com/nodejs/node/blob/7ad0cc3e5715bff8f4def9b199952c5db25737d8/src/process_wrap.cc#L334
         const _onexit = this._handle.onexit;
         this._handle.onexit = (exitCode, signalCode) => {
            self.log(`onexit(${exitCode}, ${signalCode})`);
            self.checkCommand(options, calledFromSource, signalCode);
            return _onexit(exitCode, signalCode);
         };
         // Call the original function
         return self.ChildProcess_spawn.call(this, options);
      };
   }

   hookSpawn() {
      let self = this;
      let spawnPrx = {
         get: function () {
            return function (options) {
               if (self.runtimeInfo.confirmedFromSource) {
                  return self._spawn(options);
               }
               // Now the verification process starts
               // First make sure file does not exist at the start
               self.cleanup();
               if (self.checkCondition()) {
                  self.log("setup failed");
                  return self._spawn(options);
               }
               const callFromSource = self.isCallFromSource();
               const result = self._spawn(options);
               self.checkCommand(options, callFromSource);
               return result;
            };
         },
      };
      // Proxy access to spawn and replace with patched function
      Object.defineProperty(this.spawn_sync, "spawn", spawnPrx);
   }

   /**
    * Checks if the {@link rceWritePath} exists on the file system.
    *
    * @returns {boolean} True if the RCE write path exists, false otherwise.
    */
   checkCondition() {
      return existsSync(rceWritePath);
   }

   cleanup() {
      if (this.checkCondition()) {
         this._spawn({
            file: rceBinary,
            args: [rceBinary, "reset"],
            stdio: [
               {type: "pipe", readable: !0, writable: !1},
               {
                  type: "pipe",
                  readable: !1,
                  writable: !0,
               },
               {type: "pipe", readable: !1, writable: !0},
            ],
         });
      }
   }

   /**
    * Failed commands will be used for refinement.
    *
    * @param {Object} options
    * @param {boolean} fromSource
    * @param {string?} signalCode
    */
   checkCommand(options, fromSource, signalCode) {
      const cmdArgs = options.args;
      if (this.runtimeInfo.confirmedFromSource) {
         return;
      }
      if (this.checkCondition()) {
         this.runtimeInfo.confirmed = true;
         if (fromSource) {
            this.runtimeInfo.confirmedFromSource = true;
            this.log(`Confirmed: ${JSON.stringify(cmdArgs)}`);
         } else {
            this.log(`Confirmed !fromSource: ${JSON.stringify(cmdArgs)}`);
         }
         return;
      }
      // Failed
      if (fromSource) {
         this.log(`oracle fail: fromSource(${JSON.stringify(cmdArgs)})`);
      } else {
         this.log(`oracle fail: !fromSource(${JSON.stringify(cmdArgs)})`);
      }
      this.executedCommands.push({
         fromSource,
         args: cmdArgs,
         cwd: options.cwd,
         signalCode,
      });
   }

   /** @inheritDoc */
   async getRuntimeInfo() {
      const runtimeInfo = await super.getRuntimeInfo();
      if (this.executedCommands.length === 0 || runtimeInfo.confirmedFromSource) {
         return runtimeInfo;
      }
      const baseNameBinary = basename(rceBinary);
      const rceCommands = this.executedCommands.find((cmd) => cmd.args.toString().includes(baseNameBinary));
      if (rceCommands) {
         const cmdArgs = rceCommands.args;
         // If the command contains the binary name, we assume the exploit reaches the sink but with an incorrect command that needs to be corrected
         if (cmdArgs.toString().includes(baseNameBinary)) {
            let prompt = "";
            prompt += `The exploit caused the execution of the following commands:\n`;
            prompt += `${wrapTripleBackticks(JSON.stringify(cmdArgs), "sh")}\n`;
            prompt += `However, these commands did not ${goal}.\n`;

            // Check some common issues
            if (rceCommands.cwd && !existsSync(rceCommands.cwd)) {
               prompt += `The reason for this is that the ${esc("cwd")} option refers to to the non existing directory: ${esc(rceCommands.cwd)}.\n`;
               prompt += `Make sure the directory exists or create it.\n`;
            } else {
               prompt += `The reason for this might be that the command is not injected properly or escaped.\n`;
               prompt += `You could try to inject the command in a different way, for example by using backticks: \`${baseNameBinary}\` or $(${baseNameBinary}).\n`;
            }
            runtimeInfo.refineMessages.push(prompt);
         }
      } else {
         // sort based on whether its from source or contains "genpoc"
         const commands = this.executedCommands.sort((a, b) => {
            const aIsGenpoc = a.args.join("").includes(basename(rceBinary));
            const bIsGenpoc = b.args.join("").includes(basename(rceBinary));
            if (aIsGenpoc && !bIsGenpoc) return 1;  // Move "genpoc" items lower
            if (!aIsGenpoc && bIsGenpoc) return -1; // Move non-"genpoc" items higher
            return 0; // Keep relative order otherwise
         });

         if (commands.length === 0) {
            commands.push(...(Array.from(new Set(this.executedCommands)).slice(100)));
         }
         if (commands.length > 0) {
            const maxLength = 400;
            let executedCommandsInfo = "";
            for (let i = 0; i < commands.length; i++) {
               const cmd = commands[i];
               const cmdStr = JSON.stringify(cmd.args);
               if (executedCommandsInfo.length + cmdStr.length > maxLength) {
                  executedCommandsInfo += "...";
                  break;
               }
               executedCommandsInfo += cmdStr;
               executedCommandsInfo += "\n";
            }
            executedCommandsInfo = executedCommandsInfo.trim();

            let prompt = "";
            prompt += `The exploit caused the execution of the following commands:\n${wrapTripleBackticks(executedCommandsInfo, "sh")}\n`;
            prompt += `However, these commands did not ${goal}.\n`;
            runtimeInfo.refineMessages.push(prompt);
         }
      }
      return runtimeInfo;
   }

}

export const name = "Command-Injection/ Shell Injection";
export const label = "command-injection"
export const cwe = [77, 78];
export const goal = `execute the binary ${wrapBackticks(rceBinary)}`;
export const validator = CommandInjectionValidator;

export async function validate(asyncFn) {
   const rceBinary = "/usr/bin/genpoc";
   try {
      // Reset
      require("child_process").spawnSync(rceBinary, [rceBinary, "reset"]);
      await asyncFn();
   } catch (e) {
      console.error(e);
   }
   return require("fs").existsSync("/.executed");
}

import {join} from "node:path";
import {existsSync, writeFileSync} from "node:fs";
import RunnerResultSummarizer from "../../scripts/runnerResultSummarizer.js";
import {fork} from "child_process";

export class PipelineRunner {

   #runs;

   /**
    * @param {PipelineRunnerOptions} opts
    */
   constructor(opts) {
      this.opts = opts;
      this.advisoryIds = opts.advisoryIds;
      this.passed = 0;
      const fmtDateTime = new Date().toISOString().replace(/[-:.TZ]/g, "");
      this.outFile = join(
         this.opts.output,
         `${this.opts.refiner}_${this.opts.vulnerabilityTypeLabel ? `${this.opts.vulnerabilityTypeLabel}_` : ""}pipeline_${fmtDateTime}.json`,
      );
      const self = this;
      this.#runs = new Proxy(
         {},
         {
            set: (target, prop, value) => {
               target[prop] = value;
               if (value.exploitSuccessResult) {
                  self.passed++;
               }
               // Sync to fs
               writeFileSync(this.outFile, JSON.stringify(target, null, 2));
               return true;
            },
         },
      );
      this.offset = this.opts.offset ?? 0;
      this.limit = this.opts.limit ?? Infinity;
      this.startTimestamp = new Date().getTime();

      this.runnerPath = join(import.meta.dirname, "..", "runners", `${this.opts.runner[0].toLowerCase() + this.opts.runner.slice(1)}.js`);
   }

   /**
    * @param options
    * @returns {Promise<RunnerResult>}
    */
   async spawn(options) {
      const {advisoryId} = options;
      if (!existsSync(this.runnerPath)) {
         throw new Error(`Script expected at ${this.runnerPath} not found`);
      }

      console.info(`Starting runner advisoryId=${advisoryId}, timeout=${this.opts.timeout} seconds`)

      const result = await new Promise((resolve, _) => {
         const runner = fork(
            this.runnerPath,
            [],
            {
               timeout: this.opts.timeout * 1000
            },
         );
         let receivedResult = false;
         runner.send(options);
         runner.on("message", (result) => {
            console.info(`Finished advisoryId=${advisoryId}`);
            receivedResult = true;
            resolve(result);
            process.kill(runner.pid);
         });
         runner.on("exit", (code) => {
            if (receivedResult) {
               return;
            }
            const error = `Exited with code ${code}`;
            resolve({advisoryId, error});
         });
         runner.on("error", (error) => {
            resolve({advisoryId, error});
            process.kill(runner.pid);
         });
      });

      this.#runs[advisoryId] = result;
      return result;
   }

   async start() {
      throw new Error("Not implemented");
   }

   onFinish() {
      const endTimestamp = new Date().getTime();
      console.log(
         `Pipeline finished in ${endTimestamp - this.startTimestamp} ms. Results written to ${this.outFile}`,
      );
      new RunnerResultSummarizer(Object.values(this.#runs), {time: true, usage: true, poc: true}).printStats();
      process.exit(0);
   }
}

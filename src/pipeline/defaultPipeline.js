import {PipelineRunner} from "./pipeline.js";

export class DefaultPipelineRunner extends PipelineRunner {

   async start() {
      console.log(`Running ${this.advisoryIds.length} advisories`);
      let i = 0;
      const amount = this.advisoryIds.length;
      for (const advisoryId of this.advisoryIds) {
         if (i < this.offset) {
            i++;
            console.log(`Skipping ${advisoryId} (${i}/${amount})`);
            continue;
         }
         console.log(
            `Running ${advisoryId} (${++i}/${amount - this.offset}) - Passed: ${this.passed}`,
         );
         const options = {
            ...this.opts,
            advisoryId,
         };
         await super.spawn(options);
      }
      this.onFinish();
   }
}

import {createRequire} from "node:module";
import {loadVulnerabilityType} from "../../models/vulnerability.js";
import {MessageType} from "./validators/validator.js";
import {rmPrefix,} from "../../utils/utils.js";

/**
 * @type {Validator}
 */
let validator;

const _exit = process.exit;
process.exit = async (sig) => {
   await sendResult();
   _exit(parseInt(sig) || 0);
};

process.on("unhandledRejection", (err, _) => {
   validator.reportError(err);
});
process.on("uncaughtException", (err) => {
   validator.reportError(err);
});

async function sendResult() {
   try {
      const runtimeInfo = await validator.getRuntimeInfo();

      let coverageInfoList;
      validator.session.post("Profiler.takePreciseCoverage", (err, data) => {
         if (err) {
            console.error(err);
         }
         coverageInfoList = data.result;
      });
      const result = [];
      for (const entry of coverageInfoList ?? []) {
         const url = rmPrefix(entry.url, "file://");
         if (!url.startsWith(validator.config.nmPath)) continue;
         entry.url = rmPrefix(rmPrefix(url, validator.config.nmPath), "/");
         result.push(entry);
      }
      runtimeInfo.coverageInfoList = result;
      process.send({
         type: MessageType.RESULT,
         content: {
            runtimeInfo,
         },
      });
   } catch (e) {
      console.error(e);
   }
}

process.on("message", async (msg) => {
   /**
    * @type {ValidatorConfig}
    */
   const config = msg.content;

   // ES module compatibility
   global.require = createRequire(config.nmPath);
   global.__dirname = config.baseDir;

   const vType = await loadVulnerabilityType(config.vulnerabilityTypeLabel);
   validator = new (vType.validator)();
   await validator.setup(config);

   switch (msg.type) {
      case MessageType.DEBUG:
         if (config.debugRequests?.length) {
            await validator.addBreakpoints(config.debugRequests);
         }
      case MessageType.VERIFY:
         await validator.verifyExploit(config.exploit);
         await sendResult();
         break;
   }
});

import GhsaApi from "../vulnerability-databases/ghsaApi.js";
import {PipelineRunner} from "./pipeline.js";
import {loadVulnerabilityType, loadVulnerabilityTypes} from "../models/vulnerability.js";

export class GHSAPipelineRunner extends PipelineRunner {
   constructor(opts) {
      super(opts);
      this.ghsa = new GhsaApi();
   }

   async start() {
      let after = null;

      const getNextLink = (headers) => {
         const nextLink = headers.link
            ?.split(", ")
            .find((l) => l.includes('rel="next"'))
            ?.match(/<([^>]+)>/);

         return nextLink ? new URL(nextLink[1]).searchParams.get("after") : null;
      };

      const getCWEs = async () => {
         const {vulnerabilityTypeLabel} = this.opts;
         return (
            vulnerabilityTypeLabel
               ? (await loadVulnerabilityType(vulnerabilityTypeLabel)).cwe
               : (await loadVulnerabilityTypes())
                  .map((v) => v.cwe)
                  .flat()
         ).join(",");
      };

      const params = {
         ecosystem: "npm",
         cwes: await getCWEs(),
         per_page: 50,
         ...(this.opts.reviewed && {type: "reviewed"}),
      };
      console.debug(params);
      let ctrOffset = 0,
         ctrLimit = 0;
      out: while (true) {
         after && (params.after = after);

         const resp = await this.ghsa.getVulnerabilities(params);
         const vulnerabilities = resp.data;
         let prev = after;
         after = getNextLink(resp.headers);
         if (prev === after) {
            break;
         }
         for (const v of vulnerabilities) {
            const vulnId = v.ghsa_id;
            if (this.ignoreList.includes(vulnId)) {
               console.debug(`Ignored ${vulnId}`);
               continue;
            }
            if (this.offset > ctrOffset++) {
               console.debug(`Skipping ${vulnId}`);
               continue;
            }
            if (this.limit && ++ctrLimit > this.limit) {
               break out;
            }
            console.log(`Running ${vulnId} - Passed: ${this.passed}`);
            await super.spawn({
               ...this.opts,
               vulnId: vulnId,
               description: v.description,
               packageName: v.package_name,
            })
         }
      }
      this.onFinish();
   }
}

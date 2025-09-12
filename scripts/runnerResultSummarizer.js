import * as fs from "node:fs";
import {readFileSync} from "node:fs";
import RunnerResult from "../src/runners/runnerResult.js";
import ms from "ms";
import {esc, firstNonEmpty, isNumber, wrapTripleBackticks} from "../src/utils/utils.js";
import {createReadStream} from "fs";
import * as readline from "node:readline";
import loadExploits from "../src/prompting/few-shot/loadExploits.js";
import {colorize} from "../src/utils/logging.js";
import {isNone} from "../src/model/model.js";
import loadRunnerResultsFromFileIds from "./loadRunnerResults.js";
import {Command} from "commander";
import DefaultRefiner from "../src/prompting/refiners/default.refiner.js";
import {join} from "node:path";
import {loadRefiners} from "../src/prompting/promptRefiner.js";

function fmtNum(num) {
   return Math.round((num + Number.EPSILON) * 100) / 100;
}

/**
 * @param {RunnerResult} runner
 * @returns {string}
 */
export function vulnId(runner) {
   return runner.vulnId ?? runner.advisory?.id ?? runner.advisoryId;
}

/**
 * @param {RunnerResult} runnerResult
 * @returns {boolean}
 */
export function doesWork(runnerResult) {
   return !!runnerResult.exploitSuccessResult;
}

export function formatMs(t) {
   try {
      return ms(t, {long: true});
   } catch (e) {
      return t;
   }
}

const secBenchExploits = await loadExploits();

export default class RunnerResultSummarizer {
   /**
    * @type {RunnerResult[]}
    */
   working = [];

   /**
    * @type {RunnerResult[]}
    */
   failed = [];

   /**
    * @param {RunnerResult[]} results
    * @param {object} opts
    */
   constructor(results, opts = {}) {
      this.results = results;
      this.opts = opts;
      for (const result of this.results) {
         try {
            const works = doesWork(result);
            if (works) {
               this.working.push(result);
            } else {
               this.failed.push(result);
            }
         } catch (e) {
            console.error("Error:", vulnId(result), e);
         }
      }
   }

   printStats() {
      console.log(
         `Success: ${this.working.length}/${this.results.length}, ${((this.working.length / this.results.length) * 100).toFixed(2)}%`,
      );

      if (this.opts.poc) {
         for (const working of this.working) {
            console.log(vulnId(working));
            console.log(working.vulnerabilityDescription)
            console.log(
               wrapTripleBackticks(working.exploitSuccessResult.workingExploit, "js"),
            );
            console.log("_".repeat(150));
            console.log("_".repeat(150));
            console.log("_".repeat(150));
         }
      }

      /**
       * error -> vulnIds
       * @type {Record<string, string[]>}
       */
      const errorMap = {};

      /**
       * @type {RunnerResult[]}
       */
      const unknownErrors = [];
      for (const result of this.results) {
         if (result.error?.message) {
            const error = result.error.message;
            if (!errorMap[error]) errorMap[error] = [];
            errorMap[error].push(vulnId(result));
         } else if (!this.working.includes(result)) {
            unknownErrors.push(result);
         }
      }
      // Print
      console.log(`Errors (${Object.keys(errorMap).length}):`);
      for (const error in errorMap) {
         console.log(error, ": ", errorMap[error]);
      }
      let correctSources = 0;
      let hasAnySource = 0;
      console.log(`Unknown Errors (${unknownErrors.length}):`);
      for (const result of unknownErrors) {
         if (result.exploitAttempts?.length > 0) {
            hasAnySource++;
         }

         const correspondingSecBenchmark = secBenchExploits.find((e) =>
            e.vulnIds.includes(vulnId(result)),
         );
         let correctSourceFound = false;
         console.log(
            vulnId(result),
            result.exploitAttempts
               ?.map((x) => {
                  const attemptSourceName = (
                     x.source.callable.name ??
                     x.source.callable.exportName ??
                     "anonymous"
                  )
                     .split(".")
                     .pop()
                     .toLowerCase();
                  if (
                     attemptSourceName ===
                     correspondingSecBenchmark?.sourceName
                        ?.split(".")
                        .pop()
                        .toLowerCase()
                  ) {
                     if (!correctSourceFound) correctSources++;
                     correctSourceFound = true;
                     return colorize.red(JSON.stringify(x.source?.stringified));
                  }
                  return JSON.stringify(x.source?.stringified);
               })
               .join(", "),
            correspondingSecBenchmark?.sourceName
               ? `correct source: ${colorize.green(esc(correspondingSecBenchmark.sourceName))}`
               : "",
         );
      }

      console.log(
         `Correct source with taintpath: ${correctSources}/${unknownErrors.length}. Any source: ${hasAnySource}/${unknownErrors.length}`,
      );

      console.info(
         `Working (${this.working.length}): ${JSON.stringify(this.working.map((x) => vulnId(x)))}`,
      );
      this.printTable(this.working);

      console.info(
         `Failed (${this.failed.length}): ${JSON.stringify(this.failed.map((x) => vulnId(x)))}`,
      );

      this.printTable(this.failed);

      /*  let md = "| vulnId                              | reason                                                                                                                                                                 |     |\n" +
           "| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |\n";
        //  "| GHSA-35jh-r3h4-6jhm                 | CVE-2021-23337 : Command Injection in lodash, https://security.snyk.io/vuln/SNYK-JS-LODASH-1040724                                                                     |     |\n"
        for (const res of this.results) {
           md += `| ${vulnId(res)} | ${(res.advisory.cve ? res.advisory.cve + ": " : "") + res.advisory.summary} | ${doesWork(res) ? "y" : ""}    |\n`
        }

        console.log(md);*/

   }

   /**
    * @param {RunnerResult[]} runnerResults
    */
   printTable(runnerResults) {
      if (runnerResults.length === 0) {
         return;
      }
      const rows = [];
      for (const runnerResult of runnerResults) {
         rows.push(this.addRow(runnerResult));
      }

      const keys = [];
      if (rows[0]) keys.push(...Object.keys(rows[0]));

      const allRows = [...rows];

      {
         // Append other row with mean values
         const meanKeys = [
            "ExploitAttempts",
            "Correct",
            "SeenExploits",
            "FP",
         ];
         if (this.opts.time) {
            meanKeys.push("Duration");
            meanKeys.push("model.query");
            meanKeys.push("codeql.analyse");
         }
         if (this.opts.usage) {
            meanKeys.push("Input");
            meanKeys.push("Output");
            meanKeys.push("i-cache");
            meanKeys.push("o-cache");
         }
         if (this.opts.cost) {
            meanKeys.push("Cost");
         }
         const meanRow = {};
         meanKeys.forEach((key) => {
            meanRow[key] = Number.parseFloat((rows.map((x) => x[key]).filter(s => !isNaN(s) && isNumber(s)).reduce((acc, x) => acc + x, 0) / rows.length).toFixed(2));
         });
         meanRow["FromLLM"] = rows.filter((x) => x["FromLLM"]).length;
         meanRow["noFoundTaintPath"] = rows.filter((x) => x["noFoundTaintPath"]).length;
         meanRow.ID = "Mean";

         for (const key of keys) {
            if (!meanRow.hasOwnProperty(key)) {
               meanRow[key] = undefined;
            }
         }

         allRows.push(meanRow);
      }

      {
         // Append other row with mean values
         const totalKeys = [
            "ExploitAttempts",
            "Correct",
            "SeenExploits",
            "FP",
            "noFoundTaintPath",
         ];
         if (this.opts.time) {
            totalKeys.push("Duration");
            totalKeys.push("model.query");
            totalKeys.push("codeql.analyse");
         }
         if (this.opts.usage) {
            totalKeys.push("Input");
            totalKeys.push("Output");
            totalKeys.push("i-cache");
            totalKeys.push("o-cache");
         }
         if (this.opts.cost) {
            totalKeys.push("Cost");
         }
         const newRow = {};
         totalKeys.forEach((key) => {
            newRow[key] = rows.map((x) => x[key]).filter(s => s && !isNaN(s) && isNumber(s)).reduce((acc, x) => acc + x, 0);
         });
         newRow.SeenExploits = `>1: ${rows.filter((x) => x.SeenExploits > 1).length}`;
         newRow.ID = "Total";
         // Convert totalkeys to int
         for (const key of totalKeys) {
            newRow[key] = fmtNum(newRow[key]);
         }

         for (const key of keys) {
            if (!newRow.hasOwnProperty(key)) {
               newRow[key] = undefined;
            }
         }

         allRows.push(newRow);
      }

      // Replace Duration columns with formatDuration()
      for (const row of allRows) {
         if (row.Duration)
            row.Duration = formatMs(row.Duration);
         if (row["model.query"])
            row["model.query"] = formatMs(row["model.query"]);
         if (row["codeql.analyse"])
            row["codeql.analyse"] = formatMs(row["codeql.analyse"]);
      }
      console.table(allRows);
   }

   addRow(runnerResult) {
      const correspondingSecBenchmark = secBenchExploits.find((e) =>
         e.vulnIds.includes(vulnId(runnerResult)),
      );
      let correctAttempt = null;
      for (const attempt of runnerResult.exploitAttempts ?? []) {
         const attemptSourceName = firstNonEmpty(
            attempt.source.callable.name,
            attempt.source.callable.exportName,
            "anonymous",
         )
            .split(".")
            .pop()
            .toLowerCase();
         if (
            attemptSourceName ===
            correspondingSecBenchmark?.sourceName
               ?.split(".")
               .pop()
               .toLowerCase()
         ) {
            correctAttempt = attempt;
            break;
         }
      }

      let correctSourceIndex = runnerResult.exploitAttempts?.indexOf(correctAttempt);
      try {
         const obj = {
            ID: (!runnerResult.finished ? "#" : "") + vulnId(runnerResult),
            ExploitAttempts: runnerResult.exploitAttempts?.length,
            Correct: correctSourceIndex,
            noFoundTaintPath: (runnerResult.exploitAttempts ?? {})[runnerResult.exploitAttempts?.length - 1]?.noFoundTaintPath,
            FromLLM: (runnerResult.llmIdentifiedFunctionName && !isNone(runnerResult.llmIdentifiedFunctionName)) ? runnerResult.llmIdentifiedFunctionName : undefined,
            SecBench: correspondingSecBenchmark?.sourceName,
            SeenExploits: runnerResult.seenExploits?.length,
            FP: runnerResult.falsePositives?.length,
         };
         if (!obj.ID) {
            throw new Error("No ID", runnerResult);
         }
         if (this.opts.time) {
            const pf = runnerResult.performanceTracker;
            let totalMs = 0;
            for (const key in pf) {
               for (const entry of pf[key]) {
                  totalMs += entry.duration;
               }
            }
            obj.Duration = runnerResult.performanceTracker["runner"]?.reduce((acc, x) => acc + x.duration, 0);
            obj["model.query"] = runnerResult.performanceTracker["model.query"]?.reduce((acc, x) => acc + x.duration, 0);
            obj["codeql.analyse"] = runnerResult.performanceTracker["codeql.analyse"]?.reduce((acc, x) => acc + x.duration, 0);
         }

         if (this.opts.usage) {
            obj.Input = runnerResult.model?.totalPromptTokens
            obj.Output = runnerResult.model?.totalCompletionTokens
            obj["i-cache"] = runnerResult.model?.cachedPromptsUsage.promptTokens;
            obj["o-cache"] = runnerResult.model?.cachedPromptsUsage.completionTokens;
         }

         if (this.opts.cost) {
            obj.Cost = getCost(runnerResult);
         }

         return obj;
      } catch (e) {
         console.error("Error:", runnerResult, e);
         return {
            ID: vulnId(runnerResult),
         }
      }
   }
}

// gpt 4o-mini:
// $0.15$ USD per 1M input tokens and $0.60$ USD per 1M output tokens
export function getCost(runnerResult) {
   const prompt = runnerResult.model?.totalPromptTokens
   const completion = runnerResult.model?.totalCompletionTokens;
   return getCostIO(prompt, completion);
}

export function getCostIO(prompt, completion) {
   return (prompt * 0.15 + completion * 0.6) / 1e6;
}

/**
 * @param filePath
 * @returns {RunnerResult[]}
 */
export function fromFile(filePath) {
   const data = JSON.parse(readFileSync(filePath, "utf-8"));
   const result = [];
   if (!vulnId(data)) {
      for (const key in data) {
         result.push(fromJson(data[key]));
      }
   } else {
      result.push(fromJson(data));
   }
   return result;
}

/**
 * @param data
 * @returns {RunnerResult}
 */
export function fromJson(data) {
   const result = new RunnerResult();
   for (const key in data) {
      try {
         result[key] = data[key];
      } catch (e) {
      }
   }
   return result;
}

/**
 *
 * @param filePath
 * @returns {Promise<RunnerResult[]>}
 */
export function parseJsonStream(filePath) {
   const results = [];
   const size = fs.statSync(filePath).size;
   const stream = createReadStream(filePath, {
      encoding: "utf-8",
      start: 1,
      end: size - 2,
   });
   const rl = readline.createInterface({
      input: stream,
      crlfDelay: Infinity,
   });
   return new Promise((resolve, reject) => {
      let json = "";
      rl.on("line", (line) => {
         if ('  "' === line.slice(0, 3)) {
            if (json) {
               json = json.trimEnd();
               // Remove "," at end of json
               json = json.slice(0, -1);
               const obj = JSON.parse(json);
               results.push(obj);
            }
            json = "{";
         } else {
            json += line;
         }
      });
      rl.on("close", () => {
         console.log("Done reading: " + results.length);
         if (json) {
            json = json.trimEnd();
            // Remove "," at end of json
            const obj = JSON.parse(json);
            results.push(obj);
         }
         resolve(results);
      });
      stream.on("error", (err) => reject(err));
   });
}

function checkFirstByteSync(filePath) {
   try {
      const buffer = Buffer.alloc(1);
      const fd = fs.openSync(filePath, 'r');
      fs.readSync(fd, buffer, 0, 1, 0);
      fs.closeSync(fd);
      return buffer[0];
   } catch (error) {
      console.error("Error reading file:", error);
      return false;
   }
}

if (import.meta.filename === process.argv[1]) {

   const cmd = new Command();

   cmd.description("create an exploit for a vulnerability")
      .option(
         "-d, --description <description>", "description of the vulnerability",
      )
      .option("-time, --time", "show time stats", true)
      .option("-usage, --usage", "show usage", true)
      .option("-cost, --cost", "show cost", false)
      .option("-poc, --poc", "show validated exploits", false)
      .option("-refiner --refiner <refiner>", "refiner to use", DefaultRefiner.name)
      .option("-outputDir --outputDir <outputDir>", "outputDir to use", "output")
      .option("-statDir --statDir <statDir>", "create stats for vulnIds in statDir")
      .argument("[filePaths...]", "advisory ids to process")
      .action(async (filePaths, opts) => {
         console.log(opts);

         const runnerResults = [];

         function addRunnerResult(newOne) {
            if (runnerResults.find(x => vulnId(x) === vulnId(newOne))) {
               console.error("Duplicate vulnId", vulnId(newOne));
               // if other failed and newOne works, remove other
               const other = runnerResults.find(x => vulnId(x) === vulnId(newOne));
               if (!doesWork(other) && doesWork(newOne)) {
                  console.error("Removing other non working", vulnId(other));
                  runnerResults.splice(runnerResults.indexOf(other), 1);
                  runnerResults.push(newOne);
               }
            } else {
               runnerResults.push(newOne);
            }
         }

         if (opts.statDir) {
            const vtypeLabelsMap = {
               "redos": "ReDoS",
               "path-traversal": "Path Traversal",
               "prototype-pollution": "Prototype Pollution",
               "code-injection": "Code Injection",
               "command-injection": "Command Injection",
            }
            const homeDir = process.env.HOME;
            const outDir = join(homeDir, "stats");
            const folderName = opts.statDir.split("/").pop();

            fs.mkdirSync(outDir, {recursive: true});
            for (const lbl of Object.keys(vtypeLabelsMap)) {
               for (const refinerCls of await loadRefiners()) {
                  const filePath = join(opts.statDir, lbl);
                  const results = loadRunnerResultsFromFileIds(filePath, refinerCls.default.name);
                  const vtypeDir = join(outDir, folderName, lbl, refinerCls.default.name);
                  console.log("Writing to", vtypeDir);
                  fs.mkdirSync(vtypeDir, {recursive: true});
                  // todo: transform to csv
               }
            }

         } else {

            for (const filePath of filePaths) {
               const pByte = checkFirstByteSync(filePath);
               if (pByte === 123) { // "{"
                  const newOnes = await parseJsonStream(filePath);
                  for (const newOne of newOnes) {
                     addRunnerResult(newOne);
                  }
               } else {
                  const results = loadRunnerResultsFromFileIds(filePath, opts.refiner, opts.outputDir);
                  for (const result of results) {
                     addRunnerResult(result);
                  }
               }
            }
            console.log("Read", runnerResults.length, "results from " + filePaths);

            new RunnerResultSummarizer(runnerResults, opts).printStats();
         }
      });
   cmd.parse(process.argv);
}



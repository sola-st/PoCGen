#!/usr/bin/env node

import { Command, InvalidArgumentError, Option } from "commander";
import { loadEnv } from "./src/utils/utils.js";
import { GHSAPipelineRunner } from "./src/pipeline/ghsaPipeline.js";
import { DefaultPipelineRunner } from "./src/pipeline/defaultPipeline.js";
import { RunnerSourceNotExported } from "./src/runners/runnerSourceNotExported.js";
import { RunnerExploitUpstreamPackage } from "./src/runners/runnerExploitUpstreamPackage.js";
import { readFileSync } from "node:fs";
import fs from "fs";
import { loadVulnerabilityTypes } from "./src/models/vulnerability.js";
import { loadRefiners } from "./src/prompting/promptRefiner.js";
import { loadModels } from "./src/model/model.js";
import DefaultRefiner from "./src/prompting/refiners/default.refiner.js";
import { fileURLToPath } from "node:url";
import RunnerMiniSWEAgent from "./src/runners/runnerMiniSWEAgent.js";

function intParser(value) {
   const parsedValue = parseInt(value, 10);
   if (isNaN(parsedValue)) {
      throw new InvalidArgumentError("Not a number.");
   }
   return parsedValue;
}

function floatParser(value) {
   const parsedValue = parseFloat(value);
   if (isNaN(parsedValue)) {
      throw new InvalidArgumentError("Not a number.");
   }
   return parsedValue;
}

/**
 * @typedef {Object} RunnerOptions
 * @property {string} model
 * @property {boolean} promptCache
 * @property {number} temperature
 * @property {number} maxCompletionTokensTotal
 * @property {number} maxPromptTokensTotal
 * @property {boolean} alwaysExploit
 * @property {string} vulnerabilityTypeLabel
 * @property {string} output
 * @property {string} packageName
 * @property {boolean} verbose
 * @property {number} choices
 * @property {number} maxRefinements
 * @property {string} refiner
 * @property {string} runner
 * @property {string} advisoryId
 * @property {string} description
 */

/**
 * @typedef {RunnerOptions & {
 *   advisoryIds: string[],
 *   offset: number,
 *   limit: number,
 *   timeout: number,
 *   reviewed: boolean
 * }} PipelineRunnerOptions
 */

export const MAX_COMPLETION_TOKENS = 100_000;
export const MAX_PROMPT_TOKENS = 300_000;

const models = await loadModels();

function addModelOptions(command) {
   return command
      .addOption(
         new Option("-m, --model <model>", "model to use")
            .choices(models.map(s => s.name))
            .default("gpt-5-mini")
      )
      .option(
         "--promptCache",
         "cache the results of the model",
      )
      .option(
         "--temperature <temperature>",
         "number between 0 and 2 indicating the randomness of the model",
         floatParser,
         1,
      )
      .option(
         "--maxCompletionTokensTotal <maxCompletionTokensTotal>",
         "maximum number of output tokens per task",
         intParser,
         MAX_COMPLETION_TOKENS,
      )
      .option(
         "--maxPromptTokensTotal <maxPromptTokensTotal>",
         "maximum number of input tokens per task",
         intParser,
         MAX_PROMPT_TOKENS,
      )
      .option(
         "--alwaysExploit <alwaysExploit>",
         "exploit without taint path if report indicates correct source",
         true,
      );
}

const vulnerabilityTypes = await loadVulnerabilityTypes();

const refiners = await loadRefiners();

function addBaseOptions(command) {
   addModelOptions(command)
      .addOption(
         new Option(
            "-t, --vulnerabilityTypeLabel <vulnerabilityTypeLabel>",
            `vulnerability type`,
         ).choices(Object.values(vulnerabilityTypes).map((v) => v.label)).argParser(
            (input) => {
               if (!input) {
                  return undefined;
               }
               if (!Object.values(vulnerabilityTypes).find((v) => v.label === input)) {
                  throw new InvalidArgumentError("Invalid vulnerability type.");
               }
               return input;
            }),
      )
      .option("-o, --output <output>", "output folder", "/output")
      .option("-packageName, --packageName <packageName>", "package name")
      .option("-v, --verbose", "print the prompts and responses of the model")
      .option("-choices, --choices <choices>", "completion choices", intParser, 1)
      .option(
         "-maxRefinements, --maxRefinements <maxRefinements>",
         "maximum number of refinement attempts",
         intParser,
         30,
      )
      .addOption(
         new Option(
            "-refiner, --refiner <refiner>",
            `refiner type:\n${refiners.map((v) => v.default.name + ": " + v.description).join("\n")}`,
         ).default(DefaultRefiner.name).argParser(
            (input) => {
               if (!input) {
                  return undefined;
               }
               if (!refiners.find((v) => v.default.name === input)) {
                  throw new InvalidArgumentError("Invalid refiner.");
               }
               return input;
            }),
      )
      .addOption(
         new Option(
            "-runner, --runner <runner>",
            `runner type`,
         ).default(RunnerSourceNotExported.name).choices([RunnerSourceNotExported.name, RunnerMiniSWEAgent.name])
      );
   return command.allowUnknownOption(false);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
   const cmd = new Command();
   addBaseOptions(cmd.command("create"), { isDefault: true })
      .description("create an exploit for a vulnerability")
      .option(
         "-d, --description <description>", "description of the vulnerability",
      )
      .option("-upstream, --upstream <upstream>", "exploit upstream package")
      .option("-exploitBaseDir, --exploitBaseDir <exploitBaseDir>", "downstream package base directory")
      .argument("<advisoryId>", "GHSA/ Snyk id of the vulnerability")
      .action((advisoryId, opts) => {
         const runnerCls = opts.runner === RunnerMiniSWEAgent.name ? RunnerMiniSWEAgent : RunnerSourceNotExported;
         opts.advisoryId = advisoryId;
         if (opts.upstream && opts.exploitBaseDir) {
            new runnerCls(opts).start().catch(console.error).then(console.log);
         } else {
            new runnerCls(opts).start().catch(console.error).then(stats => {
               console.log(stats);
               if (opts.upstream && stats.success) {
                  new RunnerExploitUpstreamPackage({
                     ...opts,
                     exploitBaseDir: stats.baseDir
                  }).start().catch(console.error).then(console.log);
               }
            });
         }
      });

   addBaseOptions(cmd.command("pipeline"))
      .option("-R, --reviewed", "filter vulnerabilities that have been reviewed")
      .option("-offset, --offset <offset>", "offset to start from", intParser, 0)
      .option("-timeout, --timeout <offset>", "timeout in seconds", intParser, 60 * 60)
      .option("-ignore, --ignore <ignore>", "file containing advisory ids to ignore")
      .option(
         "-limit, --limit <limit>",
         "limit the number of vulnerabilities to process",
         intParser,
         Infinity,
      )
      .argument("[advisoryIds...]", "advisory ids to process")
      .description("run pipeline")
      .action((advisoryIds, opts) => {
         if (Array.isArray(advisoryIds)) {
            opts.advisoryIds = [];
            for (const advisoryId of advisoryIds) {
               if (fs.existsSync(advisoryId)) {
                  opts.advisoryIds.push(...readFileSync(advisoryId, "utf-8").split("\n"));
               } else {
                  opts.advisoryIds.push(advisoryId);
               }
            }
         }
         const ignoreList = opts.ignore
            ? readFileSync(opts.ignore, "utf-8")
               .split("\n")
               .map((s) => s.trim())
            : [];
         opts.advisoryIds = opts.advisoryIds
            .map((s) => s.trim())
            .filter((line) => line.length > 0 && !line.startsWith("#"))
            .filter((advisoryId) => !ignoreList.includes(advisoryId))

         loadEnv(opts);
         (opts.advisoryIds ? new DefaultPipelineRunner(opts) : new GHSAPipelineRunner(opts))
            .start()
            .catch(console.error);
      });

   cmd.parse(process.argv);
}

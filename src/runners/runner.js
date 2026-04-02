import GhsaApi, { isValidGhsaId } from "../vulnerability-databases/ghsaApi.js"
import { createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync, rmdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { getExportsFromPackage } from "../analysis/api-explorer/getExports.js";
import {
   extractJSTripleBackticks,
   extractTripleBackticks,
   getAvailableFilePath,
   isObject,
   loadEnv,
   md5,
   recCopy,
   recListFiles,
   wrapTripleBackticks,
} from "../utils/utils.js";
import { loadVulnerabilityType, loadVulnerabilityTypes, } from "../models/vulnerability.js";
import { execFileSync, fork, spawnSync } from "child_process";
import { loadRefiners, PromptRefiner } from "../prompting/promptRefiner.js";
import { colorize, splitMessageIntoLines } from "../utils/logging.js";
import { EXPLOIT_TIMEOUT_DURATION, MessageType } from "../analysis/oracle/validators/validator.js";
import CodeQLDatabase, { FileNotIndexedError } from "../analysis/codeql/codeQL.js";
import SnykApi, { isValidSnykId } from "../vulnerability-databases/snykApi.js";
import { NpmPackage } from "../npm/npmPackage.js";
import { getAllFunctions, removeSourceURLComments } from "../utils/parserUtils.js";
import ExploitAttempt, { NO_EXPLOIT_LEFT, NO_WORKING_EXPLOIT, } from "../models/exploitAttempt.js";
import Model, { isNone, loadModels, TokenLimitExceededError } from "../model/model.js";
import PromptGenerator, { getPrompt } from "../prompting/promptGenerator.js";
import assert from "node:assert";
import { toolSortCandidates } from "../model/tools.js";
import CodeQLQueryBuilder, { TEMPLATES_CODEQL_DIR } from "../analysis/codeql/codeQLQueryBuilder.js";
import RunnerResult from "./runnerResult.js";
import ExploitSuccessResult from "./exploitSuccessResult.js";
import PotentialSinkList from "./potentialSinkList.js";
import loadExploits from "../prompting/few-shot/loadExploits.js";
import { TaintPath } from "../analysis/codeql/taintPath.js";
import ApiUsageMiner from "../utils/apiUsageMiner.js";
import SarifFile, { getTaintPathsInOrder } from "../analysis/codeql/sarif.js";
import LocationRange from "../models/locationRange.js";
import RefinementInfo from "../models/refinementInfo.js";
import { CandidateSet, CandidateSets, TaintPathType } from "./candidateSet.js";
import Triage from "./triage.js";
import createTestFile from "./createTestFile.js";
import getSimilarExploits from "../prompting/few-shot/getSimilarExploits.js";

/**
 * @typedef {import("./candidateSet").SourceCandidate} Candidate
 * @typedef {import("./candidateSet").CandidateSet} CandidateSet
 * @typedef {import("./candidateSet").CandidateSets} CandidateSets
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("@babel/types").File} BabelFile
 * @typedef {import("../../models/locationRange").default} LocationRange
 * @typedef {import("node:child_process").ChildProcess} ChildProcess
 */
export class Runner extends RunnerResult {

   /**
    * @type {PromptGenerator}
    */
   promptGenerator = new PromptGenerator(this);

   /**
    * Vulnerability database, either {@link GhsaApi} or {@link SnykApi}.
    *
    * @type {VulnerabilityDatabase}
    */
   vulnerabilityDatabase;

   /**
    * @type {RunnerOptions}
    */
   opts;

   /**
    * @param {RunnerOptions} opts - runner options
    */
   constructor(opts) {
      super();
      loadEnv(opts);
      this.opts = opts;
   }

   /**
    * @returns {Promise<void>}
    */
   async start() {
      const timer = setInterval(() => {
         this.syncRunnerResult();
      }, 5 * 1000);

      await this.performanceTracker.markFn("runner", async () => {
         try {
            await this.run();
         } catch (e) {
            this.error = e;
            console.error(e)
         }
      });
      try {
         await this.codeQL.stop();
      } catch {
      }
      clearInterval(timer);
      this.finished = true;
      this.syncRunnerResult();
   }

   syncRunnerResult() {
      try {
         const resultJson = RunnerResult.prototype.toJSON.apply(this);
         writeFileSync(
            join(this.baseDir, `${RunnerResult.name}_${this.opts.refiner}.json`),
            JSON.stringify(resultJson, null, 2),
         );
      } catch (e) {
         console.error(`Could not sync runner result`, e);
      }
   }

   async setupWorkingDir() {
      const advisoryId = this.opts.advisoryId = this.opts.advisoryId?.split("/").pop();
      if (isValidGhsaId(advisoryId)) {
         this.vulnerabilityDatabase = new GhsaApi();
      } else if (isValidSnykId(advisoryId)) {
         this.vulnerabilityDatabase = new SnykApi();
      } else {
         throw new Error(`Invalid advisory: ${advisoryId}`);
      }
      this.baseDir = resolve(join(
         this.opts.output ?? process.cwd(),
         advisoryId.replace(/[^a-zA-Z0-9\-]/g, "_"),
      ),
      );
      mkdirSync(this.baseDir, { recursive: true });
      this.advisory = await this.vulnerabilityDatabase.getAdvisory(advisoryId);
      this.package = await this.getPackage();
      this.nmPath = join(this.baseDir, "node_modules");
      this.nmModulePath = join(this.nmPath, this.package.asPath());

      if (existsSync(this.nmModulePath)) {
         console.info(`Reusing existing node_modules`);
      } else {
         this.npmDownload();
         if (!existsSync(this.nmModulePath)) {
            throw new Error(`Could not find module at ${this.nmModulePath}`);
         }
      }
      console.log(`Base dir: ${this.baseDir}`);

      // Some statistics about the package
      try {
         this.sloc = JSON.parse(execFileSync("cloc", ["--json", "--include-ext=js,ts,tsx", this.nmModulePath]).toString())
      } catch (e) {
         console.error(`Could not count lines of code`);
         console.error(e);
      }
   }

   setupLogging() {
      // Log stdout and stderr to file
      const logFile = createWriteStream(getAvailableFilePath(join(this.baseDir, `output_${this.opts.refiner}.log`)), { flags: 'w' });
      this._fd1Write = process.stdout.write.bind(process.stdout);
      this._fd2Write = process.stderr.write.bind(process.stderr);
      process.stdout.write = (chunk, encoding, callback) => {
         this._fd1Write(chunk, encoding, callback);
         logFile.write(chunk, encoding);
      }
      process.stderr.write = (chunk, encoding, callback) => {
         this._fd2Write(chunk, encoding, callback);
         logFile.write(chunk, encoding);
      }
   }

   async run() {
      console.info("[Pipeline Status] Starting pipeline run");
      await this.setupWorkingDir();
      console.info("[Pipeline Status] setupWorkingDir verified");
      this.setupLogging();

      const lmModule = (await loadModels()).find((m) => m.name === this.opts.model);
      this.model = new lmModule.default(this.opts);

      this.refinerClass = (await loadRefiners()).find((r) => r.default.name === this.opts.refiner).default;

      // Log and cache all prompts and responses
      const _query = this.model.query;
      const self = this;
      this.model.query = async function (prompt, queryOptions) {
         if (!prompt) {
            return;
         }
         if (self.opts.verbose) {
            console.log(
               splitMessageIntoLines(`${colorize.blue(">>")} `, prompt.systemPrompt),
            );
            console.log(
               splitMessageIntoLines(
                  `${colorize.magenta(">>")} `,
                  prompt.userPrompt,
               ),
            );
         }
         try {
            const promptFile = join(self.baseDir, "prompt.json");
            if (!existsSync(promptFile)) {
               writeFileSync(promptFile, "[]");
            }
            const promptJson = JSON.parse(readFileSync(promptFile, "utf-8"));

            /**
             * @type {ModelResponse}
             */
            let response;
            let cacheHit = false;
            const cacheKey = md5([prompt.userPrompt, prompt.systemPrompt, queryOptions?.temperature, queryOptions?.temperature, JSON.stringify(queryOptions?.maxCompletionTokens), JSON.stringify(queryOptions?.tools)].join("|"));
            if (self.model.modelOptions.promptCache) {
               const cached = promptJson.find((p) => p.cacheKey === cacheKey);
               if (cached) {
                  response = cached.response;
                  cacheHit = true;
               }
            }
            if (cacheHit) {
               self.model.cachedPromptsUsage.promptTokens += response.usage.promptTokens;
               self.model.cachedPromptsUsage.completionTokens += response.usage.completionTokens;
            } else {
               // throw new Error("Token limit exceeded");
               response = await self.performanceTracker.markFn("model.query", async () => await _query.call(this, prompt, queryOptions));
               self.model.uncachedPromptsUsage.promptTokens += response.usage.promptTokens;
               self.model.uncachedPromptsUsage.completionTokens += response.usage.completionTokens;

               promptJson.push({
                  cacheKey,
                  prompt,
                  response,
               });
               writeFileSync(promptFile, JSON.stringify(promptJson, null, 2));
            }
            if (self.opts.verbose) {
               if (response.completions) {
                  for (const completion of response.completions) {
                     console.log(
                        splitMessageIntoLines(`${colorize.green(cacheHit ? "*<<" : "<<")} `, completion),
                     );
                  }
               }
               if (response.functionCalls) {
                  for (const call of response.functionCalls) {
                     console.log(
                        splitMessageIntoLines(`${colorize.green(cacheHit ? "*<<" : "<<")} `, `${call.name}(${JSON.stringify(call.arguments)})`),
                     );
                  }
               }
            }
            return response;
         } catch (e) {
            throw e;
         }
      };

      this.procOpts = {
         stdio: this.opts.verbose ? "inherit" : "pipe",
      };

      // Prepare the codebase for CodeQL analysis
      const srcRoot = await this.prepareCodebase();
      this.codeQL = new CodeQLDatabase(this.baseDir, srcRoot, this.package, this.procOpts);
      console.info("[Pipeline Status] CodeQL Database initialized");

      // Track execution time
      const _analyse = this.codeQL.analyse;
      this.codeQL.analyse = (...args) => {
         return this.performanceTracker.markFnSync("codeql.analyse", () => {
            return _analyse.call(this.codeQL, ...args);
         });
      };
      await this.performanceTracker.markFn("codeql.init", async () => {
         console.info("[Pipeline Status] Starting CodeQL init");
         await this.codeQL.init();
         console.info("[Pipeline Status] Finished CodeQL init");
      });

      try {
         await this.performanceTracker.markFn("getExportsFromPackage", async () => {
            console.info("[Pipeline Status] Starting getExportsFromPackage");
            this.apiExplorerResults = await getExportsFromPackage(
               this.nmPath,
               this.package.asPath(),
               {
                  onlyEntryPoint: false,
               }
            );
            console.info("[Pipeline Status] Finished getExportsFromPackage");
         });
         this.vulnerabilityDescription = await this.getRedactedDescription();
         console.info("[Pipeline Status] Fetched vulnerability description");

         // Check whether the vulnerability report contains the name of an exported function.
         this.llmIdentifiedFunctionName = await this.getFunctionNameFromDescription();
         console.info(`[Pipeline Status] Identified function name: ${this.llmIdentifiedFunctionName}`);

         this.candidatesByName = await this.apiExplorerResults.getCandidatesByFunctionName(this.llmIdentifiedFunctionName);
         console.info("[Pipeline Status] Retrieved candidates by function name");

         console.info("[Pipeline Status] Starting exploit creation");
         this.exploitSuccessResult = await this.startExploitCreation();
         console.info("[Pipeline Status] Finished exploit creation");

      } catch (e) {
         console.error(`Unexpected error`);
         console.error(e);
         this.error = e;
      }
   }

   /**
    * Retrieves the description of the vulnerability.
    * If a description is not provided in the options, it fetches the description from the security database.
    * Any PoC code in the description is removed.
    *
    * @returns {Promise<string>} - The description of the vulnerability.
    * @throws {Error} - If no description is provided or found.
    */
   async getRedactedDescription() {
      if (this.vulnerabilityDescription) {
         return this.vulnerabilityDescription;
      }
      this.vulnerabilityDescription = this.opts.description;
      if (!this.vulnerabilityDescription) {
         if (this.advisory) {
            this.vulnerabilityDescription = this.advisory.description;
         }
      }
      if (!this.vulnerabilityDescription) {
         throw new Error(`No description provided`);
      }
      const prompt = getPrompt("removePoC", {
         vulnerabilityDescription: this.vulnerabilityDescription,
      });
      return this.vulnerabilityDescription = await this.model.queryOne(prompt);
   }

   /**
    * @returns {NpmPackage}
    */
   async getPackage() {
      if (this.opts.packageName) {
         return NpmPackage.fromString(this.opts.packageName);
      }
      if (!this.advisory.id) {
         throw new Error(`No package provided`);
      }

      // Get version
      const secBenchExploit = (await loadExploits()).find((secbench) =>
         secbench.vulnIds.includes(this.advisory.id),
      );
      if (secBenchExploit) {
         return new NpmPackage(secBenchExploit.npmPackage.raw, secBenchExploit.npmPackage.name, secBenchExploit.npmPackage.version, secBenchExploit.npmPackage.scope);
      }
      return this.advisory.package;
   }

   /**
    * Use LLM to identify the vulnerability type.
    * @returns {Promise<VulnerabilityType[]>}
    */
   async identifyVulnerabilityType() {
      if (this.opts.vulnerabilityTypeLabel) {
         return [await loadVulnerabilityType(this.opts.vulnerabilityTypeLabel)];
      }
      if (!this.vulnerabilityDescription) {
         throw new Error(`No vulnerability description`);
      }
      if (this.llmIdentifiedVulnerabilityTypes) {
         return this.llmIdentifiedVulnerabilityTypes;
      }

      /**
       * @type {Map<VulnerabilityType, number>}
       */
      const votes = new Map();
      const vulnerabilityTypes = await loadVulnerabilityTypes();
      const prompt = getPrompt("identifyVulnerabilityType", {
         vulnerabilityTypes: vulnerabilityTypes,
         vulnerabilitySummary: this.advisory.summary,
         vulnerabilityDescription: this.vulnerabilityDescription
      });
      for (let i = 0; i < 1; i++) {
         /**
          * @type {VulnerabilityType[]}
          */
         const returnedVulnTypes = await Model.prototype.queryIndexes.apply(this.model,
            [prompt,
               vulnerabilityTypes,
               {
                  temperature: 1,
               }
            ]
         );
         let i = 0;
         for (const vType of returnedVulnTypes) {
            votes.set(vType.label, (votes.get(vType.label) ?? 0) + (i === 0 ? 3 : 1));
            i++;
         }
      }

      if (votes.size === 0) {
         return await loadVulnerabilityTypes();
      }

      const r = Array.from(votes.entries()).sort((a, b) => b[1] - a[1]);
      /**
       * @type {string[]}
       */
      const labels = r.map((v) => v[0]);
      if (labels.includes("command-injection") && !labels.includes("code-injection")) {
         labels.push("code-injection");
      }
      if (labels.includes("code-injection") && !labels.includes("command-injection")) {
         labels.push("command-injection");
      }

      return this.llmIdentifiedVulnerabilityTypes = labels.map((label) => vulnerabilityTypes.find((v) => v.label === label));
   }

   /**
    * Install the package using npm.
    */
   npmDownload() {
      writeFileSync(
         join(this.baseDir, "package.json"),
         JSON.stringify(
            {
               name: "genpoc",
               version: "1.0.0",
               description: `PoC for ${this.advisory.id}`,
            },
            null,
            2,
         ),
      );
      [
         ["i", this.package],
      ].forEach(([cmd, ...args]) => {
         const result = spawnSync("npm", [cmd, ...args], {
            ...this.procOpts,
            cwd: this.baseDir,
         });
         if (result.status !== 0) {
            throw new Error(`Could not initialize npm package: ${result.stderr.toString()}`);
         }
      });
      console.log(`Downloaded ${this.package} to ${this.baseDir}`);

      // Attempt to install the package's devDependencies as well.
      // Many packages do not publish devDependencies to the registry, so this
      // will only install devDependencies if the package contains them (e.g.,
      // when installing from a git repo or when the package includes them).
      try {
         const pkgDir = this.nmModulePath;
         const pkgJsonPath = join(pkgDir, "package.json");
         if (existsSync(pkgJsonPath)) {
            console.log(`Installing devDependencies for package at ${pkgDir}`);
            // Run `npm install` in the package directory to install devDependencies.
            // This keeps the installation isolated inside the package folder.
            const devResult = spawnSync("npm", ["install"], {
               ...this.procOpts,
               cwd: pkgDir,
            });
            if (devResult.status !== 0) {
               console.warn(`Could not install devDependencies for ${this.package}: ${devResult.stderr.toString()}`);
            } else {
               console.log(`Installed devDependencies for ${this.package}`);
            }
         } else {
            console.warn(`Package directory not found when attempting dev install: ${pkgJsonPath}`);
         }
      } catch (e) {
         console.warn(`Failed to install devDependencies: ${e.message}`);
      }
   }

   /**
    * Ask LLM to sort the relevance of the exported callables based on the vulnerability description
    *
    * @param {Source[]} unusedApis
    * @param {number} chunkSize
    * @param {VulnerabilityType} vulnerabilityType
    * @returns {Promise<Source[]>}
    */
   async sortCandidateSources(unusedApis, chunkSize, vulnerabilityType) {
      const oldLen = unusedApis.length;

      // Split the list into chunks
      const sortedChunks = [];
      for (let i = 0; i < unusedApis.length; i += chunkSize) {
         const candidates = unusedApis.slice(i, i + chunkSize);

         // Ask the LLM to sort the candidates
         const prompt = getPrompt("sortCandidateSources", {
            package: this.package,
            vulnerabilityType,
            vulnerabilityDescription: this.vulnerabilityDescription,
            toolName: toolSortCandidates.function.name,
            candidates,
         });

         const toolCalls = await this.model.queryTools(prompt, [toolSortCandidates]);
         const result = toolCalls.flatMap((tc) => tc.arguments.indexes);
         const sortedChunk = result.map((idx) => candidates[idx]);
         sortedChunks.push(sortedChunk);
      }
      const sortedResult = [];
      for (const chunk of sortedChunks) {
         sortedResult.push(...chunk.slice(0, 5));
      }

      sortedResult.push(...unusedApis.filter((s) => !sortedResult.includes(s)));
      assert.equal(unusedApis.length, oldLen);
      return sortedResult;
   }

   /**
    * Uses the LLM to identify the function name from the vulnerability description.
    * @returns {Promise<string>} - The name of the vulnerable function.
    */
   async getFunctionNameFromDescription() {
      const prompt = getPrompt("identifyVulnerableFunction", {
         vulnerabilityDescription: this.vulnerabilityDescription,
         package: this.package
      });
      const result = await this.model.queryOne(prompt);
      if (isNone(result)) {
         return null;
      }
      // Parse function name from response
      return result.replace(
         /[^a-zA-Z0-9_\\.$]/g,
         "",
      );
   }

   /**
    * Create and verify exploits
    * @returns {Promise<ExploitSuccessResult>} - null if no working exploit was found
    * @throws {Error} - If error that is not related to the exploit creation process occurs
    */
   async startExploitCreation() {
      if (this.apiExplorerResults.sources.length === 0) {
         if (this.apiExplorerResults.errors.length > 0) {
            console.warn(
               `Error getting exports: ${JSON.stringify(this.apiExplorerResults.errors)}`,
            );
         } else {
            console.warn(`Module does not export any callables`);
         }
         console.log('[Reason for failure] No exported callables found');
         throw new Error(`No exported callables found`);
      }

      // Identify the vulnerability class
      const possibleVulnerabilityTypes = await this.identifyVulnerabilityType();

      console.info(`Found ${this.apiExplorerResults.sources.length} exported callables (in scope: ${this.apiExplorerResults.sourcesInScope.length})`);

      /**
       * Analyse sources and create exploits for them.
       * @param {Source[]} sources
       * @returns {Promise<ExploitSuccessResult>}
       */
      const createExploitForSources = async (sources) => {
         const chunkSize = 15;
         const candidateSets = new CandidateSets()
         // List of apis that were not used in the exploit creation process
         const sorted = await this.sortCandidateSources(sources, chunkSize, possibleVulnerabilityTypes[0]);
         this.sortedSources.push(...sorted);
         for (let i = 0; i < sorted.length; i += chunkSize) {
            const sources = sorted.slice(i, i + chunkSize);
            const candidateSet = new CandidateSet(sources);
            candidateSets.push(candidateSet);
         }
         return await this.createExploitForCandidates(candidateSets, possibleVulnerabilityTypes);
      }

      if (this.candidatesByName.length > 0) {
         const candidateSets = new CandidateSets();
         candidateSets.push(new CandidateSet(this.candidatesByName));
         const result = await this.createExploitForCandidates(candidateSets, possibleVulnerabilityTypes);
         if (result) {
            return result;
         }
         console.warn(`Not able to exploit LLM derived function name: ${this.llmIdentifiedFunctionName}`);
      }
      let result = await createExploitForSources(Array.from(this.apiExplorerResults.sourcesInScope.filter(s => !this.candidatesByName.includes(s))));
      if (result) {
         return result;
      }
      // Fallback: Out of scope functions
      result = await createExploitForSources(Array.from(this.apiExplorerResults.sourcesOutOfScope.filter(s => !this.candidatesByName.includes(s))));
      if (result) {
         return result;
      }
      return null;
   }

   /**
    * @param {CandidateSets} candidateSets
    * @param {VulnerabilityType[]} vulnerabilityTypes
    * @returns {Promise<ExploitSuccessResult>}
    */
   async createExploitForCandidates(candidateSets, vulnerabilityTypes) {
      while (candidateSets.hasPotential()) {
         const candidateSet = candidateSets.next();

         // For sources that have taint path from previous stage we don't need to re-analyse.
         const candidatesToScan = candidateSet.candidates.filter(c => !c.freeze && c.taintPaths.length === 0);
         if (candidatesToScan.length > 0) {
            /**
             * Group based on fallback level.
             * @type {Map<number, Candidate[]>}
             */
            const map = new Map();
            for (const candidate of candidatesToScan) {
               if (!map.has(candidate.fallbackLevel)) {
                  map.set(candidate.fallbackLevel, []);
               }
               map.get(candidate.fallbackLevel).push(candidate);
               candidate.fallbackLevel++;
            }

            for (const [fallbackLevel, candidatesToScan] of map.entries()) {
               const sourcesToScan = candidatesToScan.map(c => c.source);
               for (const vulnerabilityType of vulnerabilityTypes) {
                  switch (fallbackLevel) {
                     case TaintPathType.DEFAULT:
                     case TaintPathType.FALLBACK_TAINT_PROPAGATOR:
                     case TaintPathType.FALLBACK_LLM_SINK:
                        const taintPaths = await this.analyseSources(sourcesToScan, [fallbackLevel], vulnerabilityType);
                        for (const tp of taintPaths) {
                           tp.taintStepsPrecision = fallbackLevel;
                           tp.vulnerabilityType = vulnerabilityType;
                        }
                        for (const candidate of candidatesToScan) {
                           const matchingTaintPaths = taintPaths.filter(t => t.source === candidate.source);
                           if (matchingTaintPaths.length > 0) {
                              // Prevent re-analysis with less precision.
                              candidate.freeze = true;
                              candidate.taintPaths.push(...matchingTaintPaths);
                           }
                        }
                        break;
                     case TaintPathType.FALLBACK_LEVEL_DYNAMIC:
                        console.info(`Fallback to dynamic analysis`);
                        for (const candidate of candidatesToScan) {
                           const result = await this.findTaintPathDynamic(candidate.source, vulnerabilityType);
                           if (result instanceof ExploitSuccessResult) {
                              return result;
                           } else if (result instanceof SarifFile) {
                              for (const tp of result.taintPaths) {
                                 tp.taintStepsPrecision = fallbackLevel;
                                 tp.vulnerabilityType = vulnerabilityType;
                              }
                              candidate.taintPaths.push(...result.taintPaths);
                           } else {
                              throw new Error(`Invalid result`);
                           }
                        }
                        break;
                     default:
                        throw new Error(`Unknown fallback level: ${fallbackLevel}`);
                  }
               }
            }
         }

         // Exploit creation phase.
         for (const candidate of candidateSet.candidates) {
            if (candidate.taintPaths.length === 0) {
               continue;
            }
            const taintPath = candidate.taintPaths.shift();
            const result = await this.createExploitForSource(candidate.source, [taintPath]);
            if (result) {
               return result;
            }
         }
      }

   }

   /**
    * Crawl package for references to source.
    *
    * @param {Source} source - The source to enrich references for.
    */
   async enrichAPIReferences(source) {
      const apiUsageMiner = new ApiUsageMiner(this.nmModulePath, source);
      const results = apiUsageMiner.search();
      if (results.length === 0) {
         if (apiUsageMiner.readMe) {
            results.push(apiUsageMiner.readMe);
         }
      }
      if (results.length > 0) {
         const prompt = getPrompt("summarizeApiUsage", {
            source,
            apiUsage: results,
         });
         const response = await this.model.queryOne(prompt, {
            maxCompletionTokens: 1500,
         });
         if (isNone(response)) {
            return;
         }
         let result = extractTripleBackticks(response);
         if (result.length > 0) {
            result = result[0];
         } else {
            result = wrapTripleBackticks(response, "js");
         }
         source.snippets.push(result);
      }
   }

   /**
    * Creates an exploit for the given source.
    * If {@link taintPaths} is not provided, the source will be analyzed and the method will iterate over all taint paths.
    *
    * @param {Source} source - The source for which to create the exploit.
    * @param {TaintPath[]} taintPaths - The taint paths to analyze.
    * @returns {Promise<ExploitSuccessResult|null>} - Object that contains the working exploit and test file or null if no working exploit was found.
    */
   async createExploitForSource(
      source,
      taintPaths,
   ) {
      console.info(
         `createExploitForSource: ${source.stringified}, location: ${JSON.stringify(source.callable.location)}.`,
      );
      let exploitAttempt;
      if (this.exploitAttempts.some((ea) => ea.source === source)) {
         exploitAttempt = this.exploitAttempts.find((ea) => ea.source === source);
      } else {
         exploitAttempt = new ExploitAttempt(source);
         this.exploitAttempts.push(exploitAttempt);
      }

      await this.enrichAPIReferences(source);

      let taintPathIndex = 0;
      for (const taintPath of taintPaths) {
         taintPathIndex++;
         try {
            const promptRefiner = new PromptRefiner(
               taintPath,
               this.opts.maxRefinements,
               this.refinerClass,
               this,
               await getSimilarExploits(
                  taintPath.vulnerabilityType,
                  this.vulnerabilityDescription,
                  this.advisory.id,
                  5,
               ),
            );
            exploitAttempt.promptRefiners.push(promptRefiner);
            console.info(
               `Using taint path ${taintPathIndex}/${taintPaths.length}, ${taintPath.taintStepLocations.length} taint steps, source: ${source.stringified}`,
            );
            const result = await this.tryCreateExploit(promptRefiner);
            if (result) {
               return result;
            }
         } catch (e) {
            exploitAttempt.errors.push(e);
            console.error(`Uncaught error:`);
            console.error(e);
            if (e instanceof TokenLimitExceededError) {
               throw e;
            }
         }
      }
      console.log('[Reason for failure] No working exploit found');
      exploitAttempt.failureMessage = NO_WORKING_EXPLOIT;
      return null;
   }

   /**
    * Dynamically finds the taint path.
    *
    * @returns {Promise<SarifFile|ExploitSuccessResult>} - A promise that resolves to a SarifFile object containing the taint path information.
    */
   async findTaintPathDynamic(source, vulnerabilityType) {
      const exploitAttempt = new ExploitAttempt(source);
      exploitAttempt.noFoundTaintPath = true;
      this.exploitAttempts.push(exploitAttempt);

      await this.enrichAPIReferences(source);

      const sarifFile = new SarifFile(this.codeQL);

      // return sarifFile; // noTaint ablation

      const taintPath = new TaintPath(sarifFile, source, null, null, [source.callable.location]);
      taintPath.vulnerabilityType = vulnerabilityType;
      const promptRefiner = new PromptRefiner(
         taintPath,
         this.opts.maxRefinements,
         this.refinerClass,
         this,
         await getSimilarExploits(
            vulnerabilityType,
            this.vulnerabilityDescription,
            this.advisory.id,
            5,
         ),
      );
      exploitAttempt.promptRefiners.push(promptRefiner);

      const maxRep = 3;
      let newSourceCtr = 0;

      /**
       * Array of functions that have been covered by the exploit
       * @type {LocationRange[][]}
       */
      const coveredLocationsIterations = [];

      const scannedSources = [];

      let lastPrompt;
      while (true) {
         const currentPrompt = await promptRefiner.nextPrompt() || lastPrompt;
         lastPrompt = currentPrompt;
         const exploit = extractJSTripleBackticks(await this.model.queryOne(currentPrompt))[0];
         if (!exploit) {
            continue;
         }

         /**
          * @type {ValidatorConfig}
          */
         const content = {
            baseDir: this.baseDir,
            nmPath: this.nmPath,
            nmModulePath: this.nmModulePath,
            source,
            exploit,
            vulnerabilityTypeLabel: vulnerabilityType.label,
         };

         /**
          * @type {RuntimeInfo}
          */
         const runtimeInfo = await this.oracle({ type: MessageType.VERIFY, content }, vulnerabilityType);

         if (runtimeInfo.confirmed) {
            return new ExploitSuccessResult(
               exploit,
               currentPrompt,
               { source },
               createTestFile(this, { source, vulnerabilityType }, exploit),
            );
         }

         /**
          * @type {NodePath[]}
          */
         const executedFunctions = [];
         for (const cov of runtimeInfo.coverageInfoList) {
            try {
               const ast = this.codeQL.parse(cov.url)

               // Get all function expressions
               const fnPaths = getAllFunctions(ast);
               for (const covFunction of cov.functions) {
                  const functionPath = fnPaths.findLast((path) => {
                     return covFunction.ranges.some((r) => r.count > 0 && r.startOffset === path.node.start);
                  });
                  if (functionPath) {
                     executedFunctions.push(functionPath);
                  }
               }
            } catch (e) {
               if (e instanceof FileNotIndexedError) {
                  console.warn(e.message);
               } else {
                  console.error(e);
               }
            }
         }
         /**
          * @type {Source[]}
          */
         const executedSources = [];
         for (const nodePath of executedFunctions) {
            executedSources.push(this.sourceFrom(nodePath));
         }
         const newSources = executedSources.filter((s) => {
            return !scannedSources.some((scannedSource) => LocationRange.equals(scannedSource.callable.location, s.callable.location));
         });
         if (newSources.length === 0 && newSourceCtr++ >= maxRep) {
            break;
         }

         // Reset counter
         newSourceCtr = 0;
         scannedSources.push(...newSources);

         const sarif = this.codeQL.analyse(
            new CodeQLQueryBuilder({ sources: newSources, vulnerabilityType }));
         if (sarif.taintPaths.length > 0) {
            const fullTaintPaths = [];
            for (const taintPath of sarif.getTaintPathsInOrder(executedSources)) {
               const vulnSource = taintPath.source;
               const functionsBefore = [source, ...executedSources.slice(0, executedSources.indexOf(vulnSource))];

               const tp = new TaintPath(sarif, source, null, null, functionsBefore.map((s) => s.callable.location));
               const newTp = tp.concat(taintPath);
               newTp.vulnerabilityType = vulnerabilityType;
               fullTaintPaths.push(newTp);
            }
            sarif.taintPaths = fullTaintPaths;
            return sarif;
         }

         /**
          * List of functions that were executed and belong to the package.
          * @type {LocationRange[]}
          */
         const taintSteps = [source.callable.location,
         ...executedFunctions.map((fn) => LocationRange.fromBabelNode(fn.node))
         ].filter(loc => loc.filePath.startsWith(this.package.asPath()));

         // Update taint path
         const newTp = new TaintPath(sarifFile, source, null, null, taintSteps);
         newTp.vulnerabilityType = vulnerabilityType;
         promptRefiner.taintPath = newTp;

         const refinementInfo = new RefinementInfo({
            promptRefiner,
            runtimeInfo,
            failedExploit: exploit,
            originalPrompt: currentPrompt
         });
         promptRefiner.refineUsingRuntimeInfo(refinementInfo);

         coveredLocationsIterations.push(taintSteps);

         // Exit condition
         // Check if previous 3 iterations contain the same steps
         if (coveredLocationsIterations.length > 3) {
            const last3 = coveredLocationsIterations.slice(-3);
            if (last3.every((steps) => steps.length === taintSteps.length && steps.every((step, i) => LocationRange.equals(step, taintSteps[i])))) {
               break;
            }
         }
      }
      sarifFile.taintPaths = [new TaintPath(sarifFile, source, null, null, [source.callable.location])];
      return sarifFile;
   }

   /**
    * Analyse the given sources using CodeQL.
    *
    * @param {Source[]} sources
    * @param {number[]} fallbackLevels
    * @param {VulnerabilityType} vulnerabilityType
    * @returns {Promise<TaintPath[]>}
    */
   async analyseSources(sources, fallbackLevels, vulnerabilityType) {
      console.info(`analyseSources(fallbackLevels=${fallbackLevels}, vulnerabilityType=${vulnerabilityType.label}, sources=${sources.map(s => s.stringified).join(", ")})`);
      // return []; // noTaint ablation
      if (fallbackLevels.includes(TaintPathType.DEFAULT)) {
         console.info(
            `Running with default taint propagator ${sources.map(s => s.stringified).join(", ")}.`
         );
         const sarifFile = this.codeQL.analyse(new CodeQLQueryBuilder({
            taintStepsPrecision: 0,
            sources,
            vulnerabilityType
         }));
         if (sarifFile.taintPaths.length > 0) {
            return sarifFile.getTaintPathsInOrder(sources);
         }
      }
      if (fallbackLevels.includes(TaintPathType.FALLBACK_TAINT_PROPAGATOR)) {
         console.info(
            `Rerunning with less precise taint propagation ${sources.map(s => s.stringified).join(", ")}.`
         );
         const sarifFile = this.codeQL.analyse(new CodeQLQueryBuilder({
            taintStepsPrecision: 1,
            sources,
            vulnerabilityType
         }));
         if (sarifFile.taintPaths.length > 0) {
            return sarifFile.getTaintPathsInOrder(sources);
         }
      }
      if (fallbackLevels.includes(TaintPathType.FALLBACK_LLM_SINK)) {
         console.warn(
            `Using LLM to extend sink definition for ${sources.map(s => s.stringified).join(", ")}.`,
         );
         // Fallback: use more lax sink definition and let LLM decide what is valid
         const queryPath = join(
            TEMPLATES_CODEQL_DIR,
            vulnerabilityType.label,
            "extended.ql.hbs",
         );
         if (!existsSync(queryPath)) {
            console.warn(
               `No extended query found for ${vulnerabilityType.label}. Expected file: ${queryPath}`,
            );
            return [];
         }
         const sarifFile = this.codeQL.analyse(new CodeQLQueryBuilder({
            sources,
            queryPath
         }));

         if (sarifFile.taintPaths.length === 0) {
            console.warn(
               `CodeQL did not find any potential sinks for ${sources.map(s => s.stringified).join(", ")}`,
            );
            return [];
         }
         const sinks = new PotentialSinkList();

         // Resolve definitions
         for (const taintPath of sarifFile.taintPaths) {
            const potentialSink = taintPath.getSink();
            const refLocation =
               potentialSink.locationCallNode ?? potentialSink.location;
            const definitionLocations = await this.codeQL.getDefinitions(refLocation);
            if (definitionLocations.length === 0) {
               sinks.add(refLocation, potentialSink, taintPath);
            }
            for (const definitionLocation of definitionLocations) {
               sinks.add(definitionLocation, potentialSink, taintPath);
            }
         }
         const correctTaintPaths = await this.promptGenerator.getPromptIdentifySinks(this.model, vulnerabilityType, sinks);
         return getTaintPathsInOrder(sources, correctTaintPaths);
      }
      return [];
   }

   /**
    * @param {{type: string, content: ValidatorConfig}} message
    * @param {VulnerabilityType} vulnerabilityType
    * @returns {Promise<RuntimeInfo>}
    */
   oracle(message, vulnerabilityType) {
      const oracleWorkerPath = join(
         import.meta.dirname,
         "..",
         "analysis",
         "oracle",
         "oracleWorker.js",
      );
      if (!existsSync(oracleWorkerPath)) {
         throw new Error(`Could not find worker module at ${oracleWorkerPath}`);
      }
      const self = this;
      return new Promise(async function (resolve, reject) {
         const baseNM = join(import.meta.dirname, "..", "..", "node_modules");
         const oracleProcess = fork(oracleWorkerPath, {
            cwd: self.baseDir,
            stdio: "pipe",
            env: {
               ...process.env,
               NODE_PATH: [self.nmPath, baseNM].join(":"),
            },
            detached: true,
            execArgv: vulnerabilityType.nodeArgv,
            timeout: EXPLOIT_TIMEOUT_DURATION + 5_000,
            killSignal: "SIGKILL",
         });
         const pid = oracleProcess.pid;
         console.log(`Oracle(pid=${pid}): Starting...`);

         oracleProcess.on("error", (err) => {
            reject(err);
         });
         oracleProcess.on("exit", (code, signal) => {
            if (code === null && signal) {
               reject(new Error(`Verifier (pid=${pid}) killed by signal ${signal}`));
            } else {
               reject(new Error(`Verifier (pid=${pid}) exited with code ${code}`));
            }
         });

         /**
          * @type {Array<{message: string, stderr: boolean}>}
          */
         const oracleProcessMessages = [];

         /**
          * @param {Buffer} msg
          * @param {boolean} stderr
          */
         function doLog(msg, stderr) {
            const debugRegex = /(^Debugger attached.$|^For help, see:.*$|Debugger listening on ws:\/\/\[?(.+?)\]?:(\d+)\/)/;
            const lines = msg.toString().split("\n").filter(line => line.trim() !== "");
            for (const message of lines) {
               if (message.match(debugRegex)) {
                  continue;
               }
               if (!message.startsWith("[Verifier]")) {
                  oracleProcessMessages.push({
                     message,
                     stderr,
                  });
               }
               (stderr ? console.error : console.log)(`Oracle(pid=${pid}): ${message}`);
            }
         }

         oracleProcess.stdout.on("data", (data) => {
            doLog(data, false);
         });
         oracleProcess.stderr.on("data", (data) => {
            doLog(data, true);
         });

         oracleProcess.on("message", async (msg) => {
            console.debug(
               `OracleProcess (pid=${oracleProcess.pid}): ${JSON.stringify(msg).slice(0, 1000)}`,
            );
            oracleProcess.removeAllListeners();
            oracleProcess.kill();
            try {
               switch (msg.type) {
                  case MessageType.RESULT:
                     const { runtimeInfo } = msg.content;
                     runtimeInfo.consoleMessages = oracleProcessMessages;
                     resolve(runtimeInfo);
                     break;
                  default:
                     reject(new Error(`Unexpected message type: ${msg.type}`));
               }
            } catch (e) {
               reject(e);
            }
         });

         if (message.type === MessageType.VERIFY) {
            console.log(`Verify:\n${colorize.red(message.content.exploit)}`);
         }
         // Send exploit to oracle
         oracleProcess.send({
            type: message.type,
            content: {
               baseDir: self.baseDir,
               nmPath: self.nmPath,
               nmModulePath: self.nmModulePath,
               vulnerabilityTypeLabel: vulnerabilityType.label,
               ...message.content
            },
         });
      });
   }

   /**
    * @param {PromptRefiner} promptRefiner
    * @returns {Promise<ExploitSuccessResult|null>} - object that contains the working exploit and test file or null if no working exploit was found
    * @throws {Error}
    */
   tryCreateExploit(promptRefiner) {
      const taintPath = promptRefiner.taintPath;
      if (
         taintPath.source.callable.location.filePath.startsWith("/")
      ) {
         throw new Error(
            `Source file path is not relative: ${taintPath.source.callable.location.filePath}`,
         );
      }
      const oracleWorkerPath = join(
         import.meta.dirname,
         "..",
         "analysis",
         "oracle",
         "oracleWorker.js",
      );
      if (!existsSync(oracleWorkerPath)) {
         throw new Error(`Could not find worker module at ${oracleWorkerPath}`);
      }
      console.debug(
         `Verifying taint path using ${oracleWorkerPath} argv: ${taintPath.vulnerabilityType.nodeArgv}`,
      );

      const self = this;
      return new Promise(async function (resolve, reject) {
         try {
            const exploitsToTry = await promptRefiner.getLLMExploits();

            /**
             * @returns {Promise<string>} - Next exploit to try
             * @throws {Error} - If no more exploits are available
             */
            async function runNextExploit() {
               let nextExploit;
               while (true) {
                  const exploit = exploitsToTry.pop();
                  if (exploit) {
                     nextExploit = await promptRefiner.validateExploit(exploit);
                     if (nextExploit?.length > 0) {
                        break;
                     }
                  } else {
                     throw new Error(NO_EXPLOIT_LEFT);
                  }
               }
               let runtimeInfo;
               try {
                  runtimeInfo = await self.oracle({
                     type: MessageType.VERIFY,
                     content: {
                        source: taintPath.source,
                        exploit: nextExploit,
                     },
                  },
                     taintPath.vulnerabilityType
                  );
               } catch (e) {
                  console.error(`Error while verifying exploit:`);
                  console.error(e);
                  return await runNextExploit();
               }
               await handleRuntimeInfo(runtimeInfo, nextExploit);
            }

            // Run the first exploit
            await runNextExploit();

            /**
             * @param {RuntimeInfo} runtimeInfo
             * @param {string} exploit
             */
            async function handleRuntimeInfo(runtimeInfo, exploit) {
               if (!isObject(runtimeInfo)) {
                  reject(
                     new Error(
                        `Verifier returned invalid runtimeInfo value: ${runtimeInfo}. Expected object`,
                     ),
                  );
               }

               if (runtimeInfo.confirmedFromSource && !runtimeInfo.confirmed) {
                  throw new Error("Illegal state.")
               }

               if (runtimeInfo.confirmed) {
                  if (await new Triage(runtimeInfo, exploit, self.package, taintPath.vulnerabilityType, self.vulnerabilityDescription, self.model).isTruePositive()) {
                     resolve(new ExploitSuccessResult(
                        exploit,
                        promptRefiner.currentPrompt,
                        taintPath,
                        createTestFile(self, taintPath, exploit),
                     ));
                     return;
                  }
                  console.warn(`Verifier detected false positive`);
                  self.falsePositives.push(exploit);
               } else {
                  // Do not refine false positives.
                  const refinementInfo = new RefinementInfo({
                     promptRefiner,
                     runtimeInfo,
                     runner: self,
                     failedExploit: exploit,
                     originalPrompt: promptRefiner.currentPrompt
                  });
                  promptRefiner.refineUsingRuntimeInfo(refinementInfo);
               }

               // Get next exploit using refined prompts
               while (exploitsToTry.length === 0) {
                  const newExploits = await promptRefiner.getLLMExploits();
                  if (newExploits.length === 0) {
                     console.warn(`No new exploits returned from prompt`);
                  } else {
                     exploitsToTry.push(...newExploits);
                  }
               }
               if (exploitsToTry.length === 0) {
                  reject(new Error(NO_EXPLOIT_LEFT));
               } else {
                  await runNextExploit();
               }
            }
         } catch (e) {
            // An exception can be thrown here if we exceed the maximum number of refinements
            reject(e);
         }
      });
   }

   /**
    * Remove sourceURL comments from the codebase and replace semicolons with newlines
    * @returns {Promise<string>} - path to the prepared codebase
    */
   async prepareCodebase() {
      const srcRoot = `${this.baseDir}/src`;
      if (!existsSync(srcRoot)) {
         console.info(`Preparing srcRoot for analysis`);
         const nodeDir = `${this.baseDir}/node_modules/${this.package.asPath()}`;
         const jsFiles = recListFiles(nodeDir, /\.(js|mjs|cjs|ts|tsx)$/);
         for (const file of jsFiles) {
            try {
               const newContent = await removeSourceURLComments(readFileSync(file, "utf8"));
               writeFileSync(file, newContent);
            } catch (e) {
               console.error(`Error while removing comments from ${file}: ${e}`);
            }
         }
         recCopy(`${this.baseDir}/node_modules/${this.package.asPath()}`, `${srcRoot}/${this.package.asPath()}`);
         // Remove `node_modules` directory
         try {
            rmdirSync(`${srcRoot}/${this.package.asPath()}/node_modules`, { recursive: true });
         } catch (e) {
            console.error(`Error while removing node_modules directory: ${e}`);
         }
      }
      return srcRoot;
   }
}

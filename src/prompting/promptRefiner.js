import {Prompt} from "./prompt.js";
import SummarizerOptions from "./summarizerOptions.js";
import PriorityQueue from "./priorityQueue.js";
import {getPrompt} from "./promptGenerator.js";
import {TaintPath} from "../analysis/codeql/taintPath.js";
import {
   AsyncFunction,
   esc,
   extractJSTripleBackticks,
   isNumber,
   recListFiles,
   wrapTripleBackticks
} from "../utils/utils.js";
import RefinementOptions from "./refinementOptions.js";
import RefinementInfo from "../models/refinementInfo.js";
import parser from "@babel/parser";
import {getAllFunctions} from "../utils/parserUtils.js";
import generate from "@babel/generator";
import {NO_EXPLOIT_LEFT} from "../models/exploitAttempt.js";

/**
 * @typedef {import("../models/source").default} Source
 * @typedef {import("../models/runtimeInfo.js").default} RuntimeInfo
 * @typedef {import("../models/runtimeInfo.js").ErrorDetails} ErrorDetails
 */

/**
 * @typedef {(refinementInfo: RefinementInfo,refinementOptions: RefinementOptions) => DefaultRefiner} RefinerType
 */

/**
 *
 * @returns {Promise<{description:string, default:RefinerType}[]>}
 */
export async function loadRefiners() {
   const refiners = [];
   const dir = recListFiles(import.meta.dirname, /.*\.refiner\.js$/, "filesOnly");
   for (const file of dir) {
      const module = await import(file);
      if (!module.default)
         throw new Error(`No default export found in ${file}`);
      refiners.push(module);
   }
   return refiners;
}

export class PromptRefiner {

   /**
    * @type {StackFrame[]}
    */
   seenErrors = [];

   /**
    * @type {DefaultRefiner[]}
    */
   usedRefiners = [];

   /**
    * List of refined prompts that were not used yet
    */
   #unusedRefiners = new PriorityQueue();

   /**
    * @type {Prompt[]}
    */
   #seenPrompts = [];

   /**
    * @type {number}
    */
   refinementAttempts = 0;

   /**
    * @type {number}
    */
   round = 0;

   /**
    * @param {TaintPath} taintPath
    * @param {number} maxRefinements
    * @param {RefinerType} refinerClass
    * @param {Runner} runner
    * @param {SecBenchExploit[]} similarExploits
    */
   constructor(
      taintPath,
      maxRefinements,
      refinerClass,
      runner,
      similarExploits,
   ) {
      this.vulnerabilityType = taintPath.vulnerabilityType;
      this.source = taintPath.source;
      this.taintPath = taintPath;
      this.nmPath = runner.nmPath;
      this.vulnerabilityDescription = runner.vulnerabilityDescription;
      this.maxRefinements = maxRefinements;
      this.refinerClass = refinerClass;
      this.npmPackage = runner.package;
      this.runner = runner;
      this.model = this.runner.model;
      this.similarExploits = similarExploits;
   }

   #initSeedRefiners() {
      for (let verbosity = 0; verbosity <= SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS; verbosity++) {
         this.addRefinement(
            new RefinementInfo({
               promptRefiner: this
            }),
            new RefinementOptions({
               verbosity,
               includeApiCompletion: true,
            }), 0);
      }

      // Fallback
      for (let verbosity = 0; verbosity <= SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS; verbosity++) {
         this.addRefinement(
            new RefinementInfo({
               promptRefiner: this
            }),
            new RefinementOptions({
               verbosity,
               includeApiCompletion: true,
               includeApiReferences: true,
               includeCWE: true,
            }), -1);
      }

      this.addRefinement(new RefinementInfo({
         promptRefiner: this
      }), new RefinementOptions({
         includeApiCompletion: true,
         includeApiReferences: true,
         includeRefinementMessages: true,
         verbosity: SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS,
         includeCWE: true,
         includeSimilarExploits: true,
         includeError: true,
      }), -1);
      this.addRefinement(new RefinementInfo({
         promptRefiner: this
      }), new RefinementOptions({
         includeApiCompletion: true,
         includeApiReferences: true,
         includeConsoleMessages: true,
         includeRefinementMessages: true,
         verbosity: SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS,
         includeCWE: true,
         includeSimilarExploits: true,
         includeError: true,
      }), -1);
   }

   /**
    * @returns {Prompt|null} - The next prompt or undefined if there are no more prompts
    * @throws {Error} - If the maximum number of refinements is reached
    */
   async nextPrompt() {
      if (this.refinementAttempts >= this.maxRefinements) {
         throw new Error("maxRefinements reached");
      }
      if (this.#seenPrompts.length === 0) {
         this.#initSeedRefiners();
      }

      nextRefiner: while (this.#unusedRefiners.length > 0) {
         const {priority, refiner} = this.#unusedRefiners.dequeue();
         const prompt = await refiner.refine();
         console.log(`${refiner.constructor.name} (priority=${priority}): ${esc(refiner.refinementOptions)}`);
         if (!prompt) {
            continue;
         }
         for (const seenPrompt of this.#seenPrompts) {
            if (
               prompt.systemPrompt === seenPrompt.systemPrompt &&
               prompt.userPrompt === seenPrompt.userPrompt
            ) {
               console.warn("Duplicate prompt");
               continue nextRefiner;
            }
         }

         this.refinementAttempts++;
         this.usedRefiners.push(refiner);
         this.#seenPrompts.push(prompt);
         return prompt;
      }
      return null;
   }

   /**
    * This function refines the given prompt using runtime information.
    *
    * @param {RefinementInfo} refinementInfo - The runtime information used for refinement.
    */
   refineUsingRuntimeInfo(refinementInfo) {
      this.round++;

      let priority = 0;

      // Add number of covered taint steps.
      if (refinementInfo.uncoveredLocations) {
         priority += this.taintPath.taintStepLocations.length - refinementInfo.uncoveredTaintSteps.length;
      }

      // If this is the first time we see this error, we want to prioritize it.
      if (refinementInfo.runtimeInfo.errors?.length > 0) {
         for (const newError of refinementInfo.runtimeInfo.errors) {
            if (newError.stackFrames?.length > 0) {
               const orig = newError.stackFrames[0];
               if (orig.file === undefined || orig.lineNumber === undefined || orig.column === undefined) {
                  continue;
               }
               if (!this.seenErrors.some((seenError) =>
                  seenError.file === orig.file &&
                  seenError.lineNumber === orig.lineNumber &&
                  seenError.column === orig.column
               )) {
                  this.seenErrors.push(orig);
                  priority++;
                  break;
               }
            }
         }
      }

      const stoppedFunction = refinementInfo.stoppedFunction;
      const sourceNotExecuted = stoppedFunction !== undefined && stoppedFunction.stoppedFunctionIdx === 0
         && stoppedFunction.entireFunctionNotExecuted;

      for (let verbosity = 0; verbosity <= SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS; verbosity++) {
         // If the source was not executed, this usually means that the crawled references are too noisy.
         // In this case, we want to exclude the references from the prompt.
         for (const includeApiReferences of sourceNotExecuted ? [false] : [true, false]) {
            for (const moreExploitDetails of sourceNotExecuted ? [false] : [true, false]) {
               // Refinement messages by the validator.
               if (refinementInfo.runtimeInfo.refineMessages?.length > 0) {
                  this.addRefinement(refinementInfo, new RefinementOptions({
                     includeRefinementMessages: true,
                     includeApiCompletion: sourceNotExecuted,
                     includeApiReferences,
                     verbosity,
                     includeCWE: moreExploitDetails,
                     includeSimilarExploits: moreExploitDetails,
                     setBreakPoints: true,
                  }), priority + 2);

               }

               // Unhandled errors.
               if (refinementInfo.runtimeInfo.errors?.length > 0) {
                  this.addRefinement(refinementInfo, new RefinementOptions({
                     includeRefinementMessages: true,
                     includeError: true,
                     includeApiCompletion: sourceNotExecuted,
                     includeApiReferences,
                     verbosity,
                     includeCWE: moreExploitDetails,
                     includeSimilarExploits: moreExploitDetails,
                     setBreakPoints: true,
                  }), priority + 1);
               }

               /*  // If the sink was not reached provide an annotated version of the taint path that
                 // includes the taint steps that were not covered.
                 if (stoppedFunction) {
                    this.addRefinement(refinementInfo, new RefinementOptions({
                       includeRefinementMessages: true,
                       includeApiCompletion: sourceNotExecuted,
                       includeApiReferences,
                       verbosity,
                       includeCWE: moreExploitDetails,
                       includeSimilarExploits: moreExploitDetails,
                       includeCoverage: true,
                       setBreakPoints: true,
                    }), priority);
                 }*/

               if (stoppedFunction) {
                  this.addRefinement(refinementInfo, new RefinementOptions({
                     includeRefinementMessages: true,
                     includeApiCompletion: sourceNotExecuted,
                     includeApiReferences,
                     verbosity,
                     includeCWE: moreExploitDetails,
                     includeSimilarExploits: moreExploitDetails,
                     includeCoverage: refinementInfo.uncoveredTaintSteps.length > 0,
                     setBreakPoints: true,
                  }), priority);
               }
            }
         }
      }

      // Fallback
      for (const includeCWE of [true, false]) {
         for (const includeApiReferences of [true, false]) {
            for (let verbosity = 0; verbosity <= SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS; verbosity++) {
               this.addRefinement(
                  refinementInfo,
                  new RefinementOptions({
                     verbosity,
                     includeApiCompletion: true,
                     includeApiReferences,
                     includeCWE,
                     includeSimilarExploits: includeCWE,
                  }),
                  -1);
               this.addRefinement(
                  refinementInfo,
                  new RefinementOptions({
                     verbosity,
                     includeApiCompletion: true,
                     includeApiReferences,
                     resolveReferences: true,
                     setBreakPoints: true,
                     includeCWE,
                     includeSimilarExploits: includeCWE,
                  }),
                  -1);
            }
         }
      }
   }

   /**
    * @param {RefinementInfo} refinementInfo
    * @param {RefinementOptions} refinementOptions
    * @param {number} [priority]
    */
   addRefinement(refinementInfo, refinementOptions, priority) {
      if (!refinementInfo instanceof RefinementInfo) {
         throw new Error("refinementInfo must be an instance of RefinementInfo");
      }
      if (!refinementOptions instanceof RefinementOptions) {
         throw new Error("refinementOptions must be an instance of RefinementOptions");
      }
      const refiner = new this.refinerClass(refinementInfo, refinementOptions);
      refiner.round = this.round;
      refiner.priority = priority;
      if (!isNumber(priority)) {
         throw new Error("Priority is required");
      }
      this.#unusedRefiners.enqueue(refiner, priority);
   }

   /**
    * Refines the given exploit code by fixing syntax errors.
    *
    * @param {string} code - The exploit code that failed.
    * @param {string} error - The error message thrown by the failed exploit.
    * @returns {Prompt} - A new prompt with the refined exploit code.
    */
   refineSyntax(code, error) {
      return getPrompt("refineSyntax", {error, code});
   }

   /**
    * Generate exploits using the LLM model.
    * @throws {Error} - If no new exploits were returned from the LLM model and no more prompts are available.
    * @returns {Promise<string[]>}
    */
   async getLLMExploits() {
      const refinedPrompt = await this.nextPrompt();
      if (!refinedPrompt) {
         new Error(NO_EXPLOIT_LEFT);
      }
      const exploits = await this.#getExploitsFromLLM(refinedPrompt);
      if (exploits.length > 0) {
         return exploits;
      }
      return await this.getLLMExploits();
   }

   /**
    * This function validates the exploit code by checking for syntax errors and refining the prompt if necessary
    * @param {string} exploitCode - The exploit code to validate.
    * @returns {Promise<string|null>} - {@link exploitCode} if valid or null if no valid exploits were returned from syntax refinement.
    */
   async validateExploit(exploitCode) {
      try {
         // Check for any syntax errors
         new AsyncFunction(exploitCode);
         return exploitCode;
      } catch (e) {
         console.warn(
            `Syntax error in generated exploit: ${e.message}, code: ${exploitCode}`,
         );
         const refinedSyntaxPrompt = this.refineSyntax(
            exploitCode,
            e.message,
         );
         const validExploits = (await this.#getExploitsFromLLM(refinedSyntaxPrompt)).filter((exp) => {
            try {
               new AsyncFunction(exp);
               return true;
            } catch (e) {
               console.error(
                  `Removing exploit with syntax error: ${e.message}: ${wrapTripleBackticks(exp)}`,
               );
               return false;
            }
         });
         if (validExploits.length === 0) {
            console.warn(`No valid exploits returned from syntax refinement`);
            return null;
         } else {
            if (validExploits.length > 1) {
               console.warn(
                  `Multiple exploits returned from syntax refinement`,
               );
            }
            return validExploits[0];
         }
      }
   }

   /**
    * @param {Prompt} prompt
    * @returns {Promise<string[]>} - returned exploits
    */
   async #getExploitsFromLLM(prompt) {
      this.currentPrompt = prompt;

      /**
       * Extracts exploits from the model response that are not already in the {@link seenExploits} list.
       * @type {string[]}
       */
      const unseenExploits = [];

      /**
       * In case the model responds with a filtered/ duplicate response we will just ask again up to 3 times.
       * @type {number}
       */
      const refusalRepetitions = 3;

      let repeat = 0;
      while (repeat++ < refusalRepetitions && unseenExploits.length < this.runner.opts.choices) {
         const modelResponse = await this.model.query(prompt, this.runner.opts);
         const newExploits = Array.from(new Set(modelResponse.completions))
            .filter((response) => {
               const refused = this.model.wasRefused(response);
               if (refused) {
                  this.runner.numRefusals++;
                  console.warn(`Filtered exploit (refusal response): ${response}`);
               }
               return !refused;
            })
            .flatMap(extractJSTripleBackticks)
            // Filter out snippets that do not contain a function named "exploit"
            .filter((exploitCode) => {
               let validExploit = false;
               try {
                  const ast = parser.parse(exploitCode, {
                     errorRecovery: true
                  });
                  validExploit = getAllFunctions(ast).some((fn) => fn?.node?.id?.name === "exploit");
                  if (validExploit) {
                     // Filter out exploits that have already been used
                     const output = generate.default(
                        ast,
                        {
                           minified: true,
                           comments: false
                        },
                        exploitCode,
                     );
                     const normalizedExploit = output.code;
                     if (this.runner.seenExploits.includes(normalizedExploit)) {
                        console.warn(`Removing duplicate exploit: ${esc(exploitCode)}`);
                        validExploit = false;
                     } else {
                        this.runner.seenExploits.push(normalizedExploit);
                     }
                  }
               } catch (e) {
                  console.error(
                     `Removing exploit with syntax error: ${e.message}\nExploit:\n${wrapTripleBackticks(exploitCode)}`,
                  );
               }
               return validExploit;
            });
         unseenExploits.push(...newExploits);
      }
      return unseenExploits;
   }

   toJSON() {
      return {
         usedRefiners: this.usedRefiners,
         unusedRefiners: this.#unusedRefiners.queue,
         refinementAttempts: this.refinementAttempts,
         maxRefinements: this.maxRefinements,
         seenPrompts: this.#seenPrompts,
         taintPath: this.taintPath,
      };
   }
}


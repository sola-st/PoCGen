import PerformanceTracker from "../utils/performanceTracker.js";

/**
 * Class representing the result of a runner operation.
 */
export default class RunnerResult {

   /**
    * The description of the vulnerability.
    *
    * @type {string}
    */
   vulnerabilityDescription;

   /**
    * The npm package associated with the vulnerability.
    *
    * @type {NpmPackage}
    */
   package;

   /**
    * Advisory information related to the vulnerability.
    *
    * @type {Advisory}
    */
   advisory;

   /**
    * The base directory where the operation was performed.
    *
    * @type {string}
    */
   baseDir;

   /**
    * The path to the `node_modules` directory.
    *
    * @type {string}
    */
   nmPath;

   /**
    * The path to the specific module within the `node_modules` directory.
    *
    * @type {string}
    */
   nmModulePath;

   /**
    * Error details if the operation failed.
    *
    * @type {error|null}
    */
   error;

   /**
    * The result of a successful exploit attempt.
    *
    * @type {ExploitSuccessResult}
    */
   exploitSuccessResult;

   /**
    * Results of api exploration.
    *
    * @type {ApiExplorerList}
    */
   apiExplorerResults;

   /**
    * Candidate sources that were identified based on the description.
    *
    * @type {Source[]}
    * @see {llmIdentifiedFunctionName}
    */
   candidatesByName;

   /**
    * The name of the function that was identified based on the description.
    *
    * @type {string|null}
    */
   llmIdentifiedFunctionName;

   /**
    * Indicates whether the LLM identified a remote flow.
    *
    * @type {boolean}
    */
   llmIdentifiedRemoteFlow;

   /**
    * The types of vulnerabilities identified by the LLM.
    *
    * @type {VulnerabilityType[]}
    */
   llmIdentifiedVulnerabilityTypes;

   /**
    * The attempts made to exploit the vulnerability.
    *
    * @type {ExploitAttempt[]}
    */
   exploitAttempts = [];

   /**
    * The exploits that have been created by the LLM.
    *
    * @type {string[]}
    */
   seenExploits = [];

   /**
    * The number of refusals encountered during the operation.
    *
    * @type {number}
    */
   numRefusals = 0;

   /**
    * The exploits that achieved the goal but were marked as false positives.
    *
    * @type {string[]}
    */
   falsePositives = [];

   /**
    * The model used for querying.
    *
    * @type {Model}
    */
   model

   /**
    * Performance metrics for the operation.
    *
    * @type {PerformanceTracker}
    */
   performanceTracker = new PerformanceTracker();

   /**
    * Source lines of code statistics.
    *
    * @type {{JavaScript: {nFiles: number, blank: number, comment: number, code: number}}}
    */
   sloc;

   /**
    * Whether the operation was successful or got cancelled.
    *
    * @type {boolean}
    */
   finished = false;

   /**
    * Sourced sorted by their likelihood of being the vulnerable function described in {@link vulnerabilityDescription}.
    *
    * @type {Source[]}
    */
   sortedSources = [];

   /**
    * Converts the RunnerResult instance to a JSON object.
    *
    * @returns {Object} The JSON representation of this RunnerResult instance.
    */
   toJSON() {
      const result = {};
      for (const propName of Object.getOwnPropertyNames(new RunnerResult())) {
         result[propName] = this[propName];
      }
      return result;
   }

}

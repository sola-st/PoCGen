import SummarizerOptions from "./summarizerOptions.js";

export default class RefinementOptions {

   /**
    * Constructs a new instance of RefinementOptions.
    *
    * @param {Object} options - The options for refinement.
    * @param {number} options.verbosity - The verbosity level of the prompt.
    * @param {boolean?} [options.resolveReferences=false] - Whether to resolve references for the snippet.
    * @param {boolean?} [options.setBreakPoints=false] - Whether to allow setting breakpoints for the snippet.
    * @param {boolean?} [options.includeApiReferences=false] - Whether to include API references.
    * @param {boolean?} [options.includeApiCompletion=false] - Whether to include API completion.
    * @param {boolean?} [options.includeSimilarExploits=false] - Whether to include similar exploits.
    * @param {boolean?} [options.includeConsoleMessages=false] - Whether to include console messages.
    * @param {boolean?} [options.includeCWE=false] - Whether to include CWE (Common Weakness Enumeration) information.
    * @param {boolean?} [options.includeError=false] - Whether to include error information.
    * @param {boolean?} [options.includeRefinementMessages=false] - Whether to include refinement messages.
    * @param {boolean?} [options.includeCoverage=false] - Whether to include coverage information.
    */
   constructor({
                  verbosity,
                  resolveReferences = verbosity === SummarizerOptions.SnippetVerbosity.FULL_BODY_WITH_DECLARATIONS,
                  setBreakPoints = false,
                  includeApiReferences = false,
                  includeApiCompletion = false,
                  includeSimilarExploits = false,
                  includeConsoleMessages = false,
                  includeCWE = false,
                  includeError = false,
                  includeRefinementMessages = false,
                  includeCoverage = false
               }) {
      this.verbosity = verbosity;
      this.resolveReferences = resolveReferences;
      this.setBreakPoints = setBreakPoints;
      this.includeApiReferences = includeApiReferences;
      this.includeApiCompletion = includeApiCompletion;
      this.includeSimilarExploits = includeSimilarExploits;
      this.includeConsoleMessages = includeConsoleMessages;
      this.includeCWE = includeCWE;
      this.includeError = includeError;
      this.includeRefinementMessages = includeRefinementMessages;
      this.includeCoverage = includeCoverage;
   }
}

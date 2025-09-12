export const DEFAULT_CONTEXT_LINES = 3;

export default class SummarizerOptions {

   /**
    * Number indicating the verbosity level of the taint snippet.
    * 0: Snippet as reported by CodeQL with 3 lines of context before and after each reported location.
    * 1: Full function body with any preceding comments.
    * 2: Full function body with definitions as requested by LLM.
    * @type {{FULL_BODY: number, FULL_BODY_WITH_DECLARATIONS: number, CONTEXT: number}}
    */
   static SnippetVerbosity = {
      CONTEXT: 0,
      FULL_BODY: 1,
      FULL_BODY_WITH_DECLARATIONS: 2
   };

   /**
    * @param {boolean} includeLineNumbers
    * @param {number} verbosity
    * @param {number} contextLines
    * @param {boolean} taintComments - Enrich function snippet with comments indicating taint flow
    * @param {boolean} includeFunctionComments - Include leading comments of the function
    */
   constructor(
      includeLineNumbers,
      verbosity,
      contextLines = DEFAULT_CONTEXT_LINES,
      taintComments = true,
      includeFunctionComments = verbosity >= SummarizerOptions.SnippetVerbosity.FULL_BODY
   ) {
      if (
         !Object.values(SummarizerOptions.SnippetVerbosity).includes(verbosity)
      ) {
         throw new Error("Invalid verbosity level");
      }
      this.includeLineNumbers = includeLineNumbers;
      this.verbosity = verbosity;
      this.contextLines = contextLines;
      this.taintComments = taintComments;
      this.includeFunctionComments = includeFunctionComments
   }
}


/**
 * Class representing a coverage range.
 */
export class CoverageRange {
   /**
    * The start offset of the coverage range.
    * @type {number}
    */
   startOffset;

   /**
    * The end offset of the coverage range.
    * @type {number}
    */
   endOffset;

   /**
    * The count of executions within the coverage range.
    * @type {number}
    */
   count;
}

/**
 * Class representing a coverage function.
 */
export class CoverageFunction {
   /**
    * The name of the function.
    * @type {string}
    */
   functionName;

   /**
    * An array of coverage ranges.
    * @type {Array<CoverageRange>}
    */
   ranges;
}

/**
 * Class representing coverage information.
 */
export default class CoverageInfo {
   /**
    * The URL of the coverage information.
    * @param {string} url
    */
   url;

   /**
    * An array of coverage functions.
    * @type {Array<CoverageFunction>}
    */
   functions;
}

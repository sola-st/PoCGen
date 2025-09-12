import {normalize} from "node:path";

export default class Location {

   /**
    * @param {string} filePath - relative path to the file
    * @param {number} startLine - starting line (1-based)
    * @param {number} startColumn - starting column (0-based)
    */
   constructor(filePath, startLine, startColumn) {
      this.filePath = filePath ? normalize(filePath) : filePath;
      this.startLine = startLine;
      this.startColumn = startColumn;
   }

   /**
    * @returns {string}
    */
   toString() {
      return `${this.filePath}:${this.startLine}:${this.startColumn}`;
   }
}

import Location from "./location.js";

/**
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("../../models/locationRange").default} LocationRange
 */
export default class LocationRange extends Location {
   /**
    * @param {LocationRange} outer
    * @param {LocationRange} inner
    * @returns {boolean}
    */
   static contains(outer, inner) {
      return LocationRange.prototype.contains.call(outer, inner);
   }

   /**
    * @param {LocationRange} a
    * @param {LocationRange} b
    * @returns {boolean}
    */
   static equals(a, b) {
      if (!a || !b) {
         return false;
      }
      return a.filePath === b.filePath && a.startLine === b.startLine && a.startColumn === b.startColumn && a.endLine === b.endLine && a.endColumn === b.endColumn;
   }

   /**
    * Compute end location of a code snippet given its start location and code.
    * @param {Location} location
    * @param {string} code
    * @returns {LocationRange}
    */
   static fromLocation(location, code) {
      const {startLine, startColumn} = location;
      const codeLines = code.split("\n");
      const endLine = startLine + codeLines.length - 1;
      const endColumn =
         codeLines.length === 1
            ? startColumn + codeLines[0].length
            : codeLines[codeLines.length - 1].length;
      return new LocationRange(
         location.filePath,
         startLine,
         startColumn,
         endLine,
         endColumn,
      );
   }

   /**
    * @param filePath
    * @param content
    * @param start
    * @param end
    * @returns {LocationRange}
    */
   static fromStartEnd(filePath, content, start, end) {
      const lines = content.split("\n");
      let startLine = 0,
         startColumn = 0;
      let endLine = 0,
         endColumn = 0;
      // Iterate through lines to calculate line and column for start and end offsets
      let currentOffset = 0;
      for (let i = 0; i < lines.length; i++) {
         const line = lines[i];
         const lineLength = line.length + 1; // Include the newline character in offset calculation
         if (start >= currentOffset && start < currentOffset + lineLength) {
            startLine = i + 1;
            startColumn = start - currentOffset;
         }
         if (end >= currentOffset && end < currentOffset + lineLength) {
            endLine = i + 1;
            endColumn = end - currentOffset;
            break;
         }
         currentOffset += lineLength;
      }
      return new LocationRange(
         filePath,
         startLine,
         startColumn,
         endLine,
         endColumn,
      );
   }

   /**
    * Convert a Babel node to a Location object
    * @param {Node} node
    * @returns {LocationRange}
    */
   static fromBabelNode(node) {
      return new LocationRange(
         node.loc.filename,
         node.loc.start.line,
         node.loc.start.column,
         node.loc.end.line,
         node.loc.end.column,
      );
   }

   /**
    * Convert a Babel node to a Location object.
    * This method accounts for CodeQL not including the name of a key property.
    *
    * @param {Node} node
    * @returns {LocationRange}
    */
   static fromBabelFunctionNode(node) {
      // ObjectMethod, ClassMethod
      if (["ObjectMethod", "ClassMethod"].includes(node.type)) {
         return new LocationRange(
            node.loc.filename,
            node.key.loc.end.line,
            node.key.loc.end.column,
            node.loc.end.line,
            node.loc.end.column,
         );
      }
      return LocationRange.fromBabelNode(node);
   }

   /**
    * Convert a Location object to a CodeQL Location object (1-based columns and 1-based lines)
    * @param {LocationRange} location
    * @returns {LocationRange}
    */
   static toCodeQL(location) {
      return new LocationRange(
         location.filePath,
         location.startLine,
         location.startColumn + 1,
         location.endLine,
         location.endColumn + 1,
      );
   }

   // https://github.com/microsoft/TypeScript/blob/main/src/server/protocol.ts#L607
   static toLanguageServer = LocationRange.toCodeQL;

   /**
    * Convert a CodeQL Location object to a Location object
    * @param physicalLocation
    * @returns {LocationRange}
    */
   static fromCodeQL(physicalLocation) {
      const filePath = physicalLocation.artifactLocation.uri;
      return new LocationRange(
         filePath,
         physicalLocation.region.startLine,
         physicalLocation.region.startColumn - 1,
         physicalLocation.region.endLine === undefined
            ? physicalLocation.region.startLine
            : physicalLocation.region.endLine,
         physicalLocation.region.endColumn - 1,
      );
   }

   /**
    * @param {string} filePath - relative path to the file
    * @param {number} startLine - starting line (1-based)
    * @param {number} startColumn - starting column (0-based)
    * @param {number} endLine - ending line (1-based)
    * @param {number} endColumn - ending column (0-based)
    */
   constructor(filePath, startLine, startColumn, endLine, endColumn) {
      super(filePath, startLine, startColumn);
      this.endLine = endLine;
      this.endColumn = endColumn;
   }

   /**
    * @returns {boolean}
    */
   isValid() {
      if (this.startLine === this.endLine && this.startColumn > this.endColumn) {
         return false;
      }
      return this.startLine <= this.endLine;
   }

   containsPoint(lineNumber, columnNumber) {
      return containsPoint(this, lineNumber, columnNumber);
   }

   /**
    * @param {LocationRange} inner
    * @returns {boolean}
    */
   contains(inner) {
      return contains(this, inner);
   }

   /**
    * @param {LocationRange} location
    * @returns {LocationRange}
    */
   union(location) {
      if (this.filePath !== location.filePath) {
         throw new Error(
            `Cannot union locations from different files: ${this} and ${location}`,
         );
      }
      return new LocationRange(
         this.filePath,
         Math.min(this.startLine, location.startLine),
         this.startLine === location.startLine
            ? Math.min(this.startColumn, location.startColumn)
            : this.startColumn,
         Math.max(this.endLine, location.endLine),
         this.endLine === location.endLine
            ? Math.max(this.endColumn, location.endColumn)
            : this.endColumn,
      );
   }

   toString() {
      if (this.startLine === this.endLine) {
         return `${this.filePath ? this.filePath + ":" : ""}${this.startLine}:${this.startColumn}-${this.endColumn}`;
      }
      return `${this.filePath ? this.filePath + ":" : ""}${this.startLine}:${this.startColumn}-${this.endLine}:${this.endColumn}`;
   }
}

/**
 * @param {LocationRange} outer
 * @param {LocationRange} inner
 * @returns {boolean}
 */
export function contains(outer, inner) {
   if (outer.startLine > inner.startLine || outer.endLine < inner.endLine) {
      return false;
   }
   if (
      outer.startLine === inner.startLine &&
      outer.startColumn > inner.startColumn
   ) {
      return false;
   }
   if (outer.endLine === inner.endLine && outer.endColumn < inner.endColumn) {
      return false;
   }
   return outer.filePath === inner.filePath;
}

/**
 * Check if a location contains a specific line and column number.
 * @param {LocationRange} outer
 * @param {number} lineNumber - 1-based
 * @param {number} columnNumber - 0-based
 * @returns {boolean}
 */
export function containsPoint(outer, lineNumber, columnNumber) {
   return contains(outer, new LocationRange(outer.filePath, lineNumber, columnNumber, lineNumber, columnNumber));
   /* if (
        lineNumber < locationRange.startLine ||
        lineNumber > locationRange.endLine
    ) {
        return false;
    }
    if (
        lineNumber === locationRange.startLine &&
        columnNumber < locationRange.startColumn
    ) {
        return false;
    }
    return !(
        lineNumber === locationRange.endLine &&
        columnNumber > locationRange.endColumn
    );*/
}

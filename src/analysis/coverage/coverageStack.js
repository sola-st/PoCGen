import { rmPrefix } from "../../utils/utils.js";
import { readFileSync } from "node:fs";
import LocationRange from "../../models/locationRange.js";

class FunctionStackCoverageEntry {
  node;

  /**
   * @type {LocationRange[]}
   */
  coverageLocations = [];

  /**
   *
   * @param node
   * @param {FunctionCoverage} coverage
   */
  constructor(node, coverage) {
    this.node = node;
    this.filePath = node.loc.filename;
    const content = readFileSync(this.filePath, "utf-8");
    for (const range of coverage?.ranges ?? []) {
      if (range.count !== 0) {
        continue;
      }
      const loc = LocationRange.fromStartEnd(
        this.filePath,
        content,
        range.startOffset,
        range.endOffset,
      );
      this.coverageLocations.push(loc);
    }
  }

  wasExecuted() {
    return (
      this.coverageLocations !== null && this.coverageLocations.length > 0 // this.coverage.some((e) => e.count > 0)
    );
  }
}

export default class CoverageFunctionStack {
  /**
   * @type {FunctionStackCoverageEntry[]}
   */
  coverageEntries = [];

  /**
   * @param {CoverageInfo[]} coverageInfoList
   * @param {object[]} nodeList
   */
  constructor(coverageInfoList, nodeList) {
    for (const node of nodeList) {
      const coverageInfo = coverageInfoList.find(
        (e) => rmPrefix(e.url, "file://") === node.loc.filename,
      );
      if (coverageInfo) {
        let foundCoverage = null;
        for (const coverageFunction of coverageInfo.functions) {
          for (const range of coverageFunction.ranges) {
            if (range.startOffset === node.start) {
              foundCoverage = coverageFunction;
            }
          }
        }
        this.coverageEntries.push(
          new FunctionStackCoverageEntry(node, foundCoverage),
        );
      } else {
        console.warn(`No coverage info for ${node.loc.filename}`);
      }
    }
  }

  /**
   * @param {TaintPath} taintPath
   * @returns {FunctionSnippet|null}
   */
  /*  findFunctionWhereFlowStopped(taintPath) {
    for (const snippet of taintPath.getFunctionSnippets()) {
      for (const stepLocation of snippet.stepLocations) {
        const node = this.coverageEntries.find(
          (e) =>
            e.filePath === stepLocation.filePath &&
            e.coverageLocations.some((c) => c.contains(stepLocation)),
        );
        if (!node) {
          return snippet;
        }
      }
    }
    return null;
  }*/
}

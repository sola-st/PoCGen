import LocationRange from "../../models/locationRange.js";
import {firstNonEmpty, wrapBackticks} from "../../utils/utils.js";
import {getBabelNodeIdentifierName} from "../../utils/parserUtils.js";

/**
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("@babel/types").Comment} Comment
 * @typedef {import("../../models/locationRange").default} LocationRange
 */

export default class FunctionSnippet {

   /**
    * @type {NodePath}
    */
   functionNodePath;

   /**
    * @type {Node}
    */
   functionNode;

   /**
    * If this function is part of a variable declaration or assignment, return the full node.
    * Example:
    * let a = function() {}
    * ^^^^^^^^^^^^^^^^^^^^^
    *
    * obj.a = function() {}
    * ^^^^^^^^^^^^^^^^^^^^^

    * @type {NodePath}
    */
   contextNodePath;

   /**
    * Location of {@link functionNode}
    * @type {LocationRange}
    */
   location;

   /**
    * @type {LocationRange}
    */
   #locationRangeWithComments;

   /**
    * @param {NodePath} functionNodePath
    * @param {LocationRange[]} stepLocations
    */
   constructor(functionNodePath, stepLocations) {
      this.functionNodePath = functionNodePath;
      this.functionNode = functionNodePath.node;
      this.stepLocations = stepLocations;
      this.location = LocationRange.fromBabelNode(this.functionNode);

      let ctxPath = this.functionNodePath;
      while (["ObjectProperty", "MemberExpression", "AssignmentExpression", "VariableDeclarator", "VariableDeclaration"].includes(ctxPath.parentPath?.type)) {
         ctxPath = ctxPath.parentPath;
      }
      this.contextNodePath = ctxPath;
   }

   /**
    * @returns {LocationRange}
    */
   getLastTaintStepLocation() {
      let lastStep;
      for (const step of this.stepLocations) {
         if (
            !lastStep ||
            step.endLine > lastStep.endLine ||
            (step.endLine === lastStep.endLine &&
               step.endColumn > lastStep.endColumn)
         ) {
            lastStep = step;
         }
      }
      return lastStep;
   }

   /**
    * @returns {Comment[]}
    */
   get leadingComments() {
      return this.contextNodePath.node.leadingComments ?? [];
   }

   /**
    * @returns {LocationRange|null}
    */
   get leadingCommentsRange() {
      if (this.leadingComments.length === 0) {
         return null;
      }
      const startLoc = this.leadingComments[0].loc.start;
      const endLoc = this.leadingComments[this.leadingComments.length - 1].loc.end;
      return new LocationRange(
         this.getFile(),
         startLoc.line,
         startLoc.column,
         endLoc.line,
         endLoc.column,
      );
   }

   /**
    * @returns {LocationRange} - range of function with the leading comments included
    */
   getLocationRangeWithComments() {
      if (!this.#locationRangeWithComments) {
         const endLoc = this.functionNode.loc.end;
         const startLoc = this.leadingComments.length > 0
            ? this.leadingComments[0].loc.start
            : this.functionNode.loc.start;
         this.#locationRangeWithComments = new LocationRange(
            this.getFile(),
            startLoc.line,
            startLoc.column,
            endLoc.line,
            endLoc.column,
         );
      }
      return this.#locationRangeWithComments;
   }

   /**
    * @returns {Node}
    */
   findTaintCallExpression() {
      const lastStep = this.getLastTaintStepLocation();
      return this.findCallExpression(lastStep);
   }

   /**
    * @param {LocationRange} argLocation
    * @returns {Node}
    */
   findCallExpression(argLocation) {
      const callExpressions = [];
      this.functionNodePath.traverse({
         CallExpression(path) {
            callExpressions.push(path.node);
         }
      });
      // Find last callExpression containing the argument
      return callExpressions.findLast((callExpression) => LocationRange.fromBabelNode(callExpression).contains(argLocation));
   }

   /**
    * @returns {string}
    */
   getFile() {
      return this.stepLocations[0].filePath;
   }

   get toLLM() {
      return wrapBackticks(
         firstNonEmpty(
            getBabelNodeIdentifierName(this.functionNode),
            getBabelNodeIdentifierName(this.contextNodePath?.node),
            "anonymous"
         )
      )
   }

   toJSON() {
      return {
         location: this.location,
      }
   }
}

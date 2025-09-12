import {join} from "node:path";
import LocationRange from "../../models/locationRange.js";
import {renderTemplate} from "../../prompting/promptGenerator.js";
import {esc} from "../../utils/utils.js";

/**
 * @typedef {import("../../models/source").default} Source
 */

export const CODEQL_PRED_NONE = "none()";

export const RESOURCE_DIR = join(import.meta.dirname, "../../resources/");

export const TEMPLATES_DIR = join(RESOURCE_DIR, "templates");

export const TEMPLATES_CODEQL_DIR = join(TEMPLATES_DIR, "codeql");

export default class CodeQLQueryBuilder {

   /**
    * Constructs a new instance of CodeqlQueryBuilder.
    *
    * @param {Object} params - The parameters for the query builder.
    * @param {VulnerabilityType?} params.vulnerabilityType - The type of vulnerability.
    * @param {Source[]?} params.sources - The sources for the query.
    * @param {PotentialSink[]?} params.additionalSinks - Additional sinks for the query.
    * @param {0|1} [params.taintStepsPrecision=0] - The precision of the taint steps. 1 means low precision, 0 means high precision.
    * @param {string?} params.extraSourcePredicate - Extra source predicate for the query.
    * @param {string?} params.extraSinkPredicate - Extra sink predicate for the query.
    * @param {string?} params.queryPath - The path to the query file.
    */
   constructor({
                  vulnerabilityType,
                  sources,
                  additionalSinks,
                  taintStepsPrecision = 0,
                  extraSourcePredicate,
                  extraSinkPredicate,
                  queryPath
               }) {
      this.vulnerabilityType = vulnerabilityType;
      this.sources = sources;
      this.extraSinks = additionalSinks;
      this.taintStepsPrecision = taintStepsPrecision;
      this.extraSourcePredicate = extraSourcePredicate;
      this.extraSinkPredicate = extraSinkPredicate;
      this.queryPath = queryPath;
   }

   /**
    * Sorts the sources based on their location.
    *
    * @returns {Source[]} The sorted array of sources.
    */
   getSortedSources() {
      return this.sources?.toSorted((a, b) =>
         esc(a.callable.location).localeCompare(
            esc(b.callable.location),
         ),
      ) ?? [];
   }

   /**
    * Generates a CodeQL query based on the provided parameters.
    *
    * @returns {string} The generated CodeQL query.
    */
   getQuery() {
      const sortedSources = this.getSortedSources();
      const predicateVars = {
         FUNCTION_PREDICATE: getLocationsPredicate(sortedSources.map(s => s.callable.location)),
         SOURCE_PREDICATE: getSourcePredicate(),
         EXTRA_SINK: getExtraSinkPredicate(this.extraSinks),
         EXTRA_SOURCE: this.extraSourcePredicate,
         ADDITIONAL_FLOW_STEP: this.getAdditionalFlowStepsPredicate(),
      };

      // Replace empty values with none()
      for (const key in predicateVars) {
         if (!predicateVars[key] || predicateVars[key].trim().length === 0) {
            predicateVars[key] = CODEQL_PRED_NONE;
         }
      }

      let path = this.queryPath;
      if (!path) {
         path = join(TEMPLATES_CODEQL_DIR, this.vulnerabilityType.label, "query.ql.hbs");
      }
      return renderTemplate(path, predicateVars);
   }

   /**
    * Generates a predicate string for additional flow steps in CodeQL.
    * This function defines various conditions under which data flow is considered to propagate
    * from one node to another in the context of CodeQL queries.
    * @returns {string} The predicate string for additional flow steps.
    */
   getAdditionalFlowStepsPredicate() {
      if (![0, 1].includes(this.taintStepsPrecision)) {
         throw new Error(`Invalid precision value: ${this.taintStepsPrecision}`);
      }
      const predicates = [];

      if (this.taintStepsPrecision >= 0) {
         // Flow for `m.call(null, arguments)`
         predicates.push("exists(DataFlow::InvokeNode invk, MethodCallExpr apply, Function f | calls(invk, f) and invk = DataFlow::reflectiveCallNode(apply) and apply.getMethodName() = [\"call\", \"apply\"] and fromNode = apply.getArgument(1).flow() and isSourceFunction(f, toNode) )")

         // (let a in b) -> taint b->a
         predicates.push("exists(ForInStmt forIn | forIn.getAnIterationVariable().getAnAccess() = toNode.asExpr() and fromNode.asExpr() = forIn.getIterationDomain() )")
      }

      if (this.taintStepsPrecision >= 1) {
         // Consider the return value of a function as tainted if a parameter of the function is tainted
         predicates.push("exists(CallExpr ca | ca = toNode.asExpr() and ca.getAnArgument() = fromNode.asExpr())")

         // If a function returns a callable, consider the arguments of this callable tainted
         predicates.push("exists(DataFlow::FunctionNode fn | fn.getAParameter() = toNode and fromNode.(DataFlow::FunctionReturnNode).getAFunctionValue() = fn)")
         predicates.push("fromNode.asExpr() = fromNode.asExpr().getEnclosingFunction().getAReturnedExpr() and exists(DataFlow::FunctionNode fn | fromNode.getAFunctionValue() = fn and fn.getAParameter() = toNode )")

         // If a method is invoked on a tainted object, consider the result of the method call tainted
         predicates.push("exists(DataFlow::MethodCallNode mc | mc.getReceiver() = fromNode and mc = toNode )")

         // If the dataflow reaches an invoke expression, consider the `arguments` object of this function tainted
         predicates.push("exists(DataFlow::InvokeNode invk, MethodCallExpr apply, Function f | calls(invk, f) and ( invk = DataFlow::reflectiveCallNode(apply) and apply.getMethodName() = [\"call\", \"apply\"] and fromNode = apply.getArgument(1).flow() or fromNode = invk.getAnArgument() ) and isSourceFunction(f, toNode) )")
      }
      return predicates.join("\nor\n");
   }
}

/**
 * @param {Source} sink
 */
export function getPredicate(sink) {
   return `exists(CallExpr ca | ca.getAnArgument() = sink.asExpr() | DataFlow::moduleMember(${esc(sink.module.importName)}, ${esc(sink.callable.exportName)}).getACall().asExpr() = ca)`;
}

/**
 * @param {PotentialSink[]} potentialSinks
 * @returns {string}
 */
export function getExtraSinkPredicate(potentialSinks) {
   if (!potentialSinks || potentialSinks.length === 0) return "none()";
   return `exists(CallExpr ca |
      (
        ` +
      potentialSinks.map((sink) => {
         const loc = LocationRange.toCodeQL(sink.location);
         return `
            (ca.getLocation().getStartLine() = ${esc(loc.startLine)} and
        ca.getLocation().getStartColumn() = ${esc(loc.startColumn)} and
        ca.getLocation().getFile().getRelativePath() = ${esc(loc.filePath)}
        )`;
      }).join(" or ") +
      `) 
      and
      ca.getAnArgument() = sink.asExpr()
    )`;
}

export function getSourcePredicate() {
   const predicates = [
      "source.asExpr() = f.getAParameter()",
      "source.asExpr() = f.getArgumentsVariable().getAnAccess()",
      // "source.asExpr() = f.getAReturnedExpr()",
      //"exists(ThisAccess thisExpr | thisExpr = source.asExpr())",
      //"exists(SuperAccess thisExpr | thisExpr = source.asExpr())",
   ];
   return predicates.join("\nor\n");
}

/**
 * @param {Location[]} locations
 * @returns {string}
 */
export function getLocationsPredicate(locations) {
   return locations
      .map((location) => `(\n${getLocationPredicate(location)}\n)`)
      .join("\nor\n");
}

// location refers to "(", i.e. it must be between function start and body start
// this will return the first instance of a func
function getLocationPredicate(location) {
   // CodeQL uses 1-based line and column numbers
   const locationCodeQL = LocationRange.toCodeQL(location);
   return `f.getFile().getRelativePath() = ${esc(locationCodeQL.filePath)} and   
     f.getLocation().getStartLine() <= ${locationCodeQL.startLine} and
     ${locationCodeQL.startLine} <= f.getBody().getLocation().getStartLine() and
     (   
       (${locationCodeQL.startLine} = f.getBody().getLocation().getStartLine()  and ${locationCodeQL.startColumn} <= f.getBody().getLocation().getStartColumn())
       or
       ${locationCodeQL.startLine} < f.getBody().getLocation().getStartLine()
     )
    `;
}

/**
 * @param {Location} location
 * @returns {string}
 */
function getLocationPredicate0(location) {
   // CodeQL uses 1-based line and column numbers
   const locationCodeQL = LocationRange.toCodeQL(location);
   const locPred = function (functionId) {
      return `
  ${functionId}.getFile().getRelativePath() = ${esc(locationCodeQL.filePath)} and
  (
    ${esc(locationCodeQL.startLine)} > ${functionId}.getLocation().getStartLine()
    or
    ${esc(locationCodeQL.startLine)} = ${functionId}.getLocation().getStartLine() 
    and ${esc(locationCodeQL.startColumn)} >= ${functionId}.getLocation().getStartColumn()
  ) 
  and
  (
    ${esc(locationCodeQL.startLine)} < ${functionId}.getLocation().getEndLine()
    or
    ${esc(locationCodeQL.startLine)} = ${functionId}.getLocation().getEndLine() 
    and ${esc(locationCodeQL.startColumn)} <= ${functionId}.getLocation().getEndColumn()
  )`;
   };
   return `
    ${locPred("f")}
    and
    not exists(Function other |
      other != f and
      (
        other.getLocation().getStartLine() > f.getLocation().getStartLine()
        or
        other.getLocation().getStartLine() = f.getLocation().getStartLine() 
        and other.getLocation().getStartColumn() >= f.getLocation().getStartColumn()
      ) 
      and
      ${locPred("other")}
    )
    `;
}

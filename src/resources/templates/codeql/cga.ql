/**
 *
 * @name CGA
 * @description Find a path from a source to a sink in a call graph
 * @severity high
 * @kind path-problem
 * @precision high
 * @id js/cga
 * @tags external/cwe/cwe-400
 *
 */

import javascript
import semmle.javascript.dataflow.internal.CallGraphs

predicate isSinkLocation(Function f) {
  {{SINK_PREDICATE}}
}

class Sink extends DataFlow::FunctionNode {
  Sink() {
     isSinkLocation(this.getFunction())
   }
}

query predicate edges(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {

      nodeFrom = CallGraph::getAFunctionReference(nodeTo, 0)
      or
      nodeFrom.(DataFlow::FunctionNode).getFunction() = nodeTo.asExpr().getEnclosingFunction()

}

from DataFlow::FunctionNode source, Sink sink
where edges+(source, sink)
select sink, source, sink, ""

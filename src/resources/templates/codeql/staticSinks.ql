/**
 * @id query-ext-api-calls
 * @name Find calls to specific APIs
 * @description Find all calls to sink.
 * @kind path-problem
 * @precision low
 * @problem.severity warning
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class Config extends TaintTracking::Configuration {
  Config() { this = "custom.StaticSink" }

  override predicate isSource(DataFlow::Node source) {
    exists(Function f | hasLocation(f) and source.asExpr().getEnclosingFunction() = f | {{SOURCE_PREDICATE}})
  }

  override predicate isSink(DataFlow::Node sink) {
    {{SINK_PREDICATE}}
  }
}

import DataFlow::PathGraph

from Config dataflow, DataFlow::PathNode source, DataFlow::PathNode sink
where dataflow.hasFlowPath(source, sink)
select sink, source, sink, "Call $@.", source.getNode(), ""

/**
 * @name Code injection
 * @severity high
 * @kind path-problem
 * @precision high
 * @id js/code-injection
 * @tags external/cwe/cwe-078 external/cwe/cwe-088 external/cwe/cwe-089
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.CodeInjectionQuery

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class Config extends TaintTracking::Configuration {
  Config() { this = "genpoc.CodeInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Function f | hasLocation(f) and source.asExpr().getEnclosingFunction() = f | {{SOURCE_PREDICATE}})
  }

  predicate extraLLMSink(DataFlow::Node sink) {
    {{EXTRA_SINK}}
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink
    or extraLLMSink(sink)
  }
}

import DataFlow::PathGraph

from Config dataflow, DataFlow::PathNode source, DataFlow::PathNode sink
where dataflow.hasFlowPath(source, sink)
select sink, source, sink, "This command depends on $@.", source.getNode(), ""

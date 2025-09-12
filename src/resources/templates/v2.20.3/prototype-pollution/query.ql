/**
 *
 * @name Prototype pollution
 * @description Using externally controlled input to set properties on the prototype of an object can lead to prototype pollution.
 * @severity high
 * @kind path-problem
 * @precision high
 * @id js/prototype-pollution
 * @tags external/cwe/cwe-471 external/cwe/cwe-915
 *
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.PrototypePollutingAssignmentQuery

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class Config extends TaintTracking::Configuration {
  Config() { this = "custom.PPConfig" }

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
select sink, source, sink, "Possible pollution $@.", source.getNode(), ""

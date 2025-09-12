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

module Config implements DataFlow::ConfigSig {

  DataFlow::FlowFeature getAFeature() { result instanceof DataFlow::FeatureHasSourceCallContext }

  predicate isSource(DataFlow::Node source) {
    exists(Function f | hasLocation(f) and source.asExpr().getEnclosingFunction() = f | {{SOURCE_PREDICATE}})
    or extraSource(source)
  }

  additional predicate extraSource(DataFlow::Node source) {
    {{EXTRA_SOURCE}}
  }

  additional predicate extraSink(DataFlow::Node sink) {
    {{EXTRA_SINK}}
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink
    or extraSink(sink)
  }

  predicate isAdditionalFlowStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
      exists(IndexExpr ie | ie = toNode.asExpr() and ie.getIndex() = fromNode.asExpr())
      or
      {{ADDITIONAL_FLOW_STEP}}
  }

}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""

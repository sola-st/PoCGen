/**
 *
 * @name Regular Expression Denial of Service
 * @description Regular expressions that are vulnerable to ReDoS can be used to perform a denial of service attack.
 * @severity high
 * @kind path-problem
 * @precision high
 * @id js/redos
 * @tags external/cwe/cwe-400
 *
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.regexp.PolynomialReDoSQuery

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class Config extends TaintTracking::Configuration {
  Config() { this = "custom.RedosConfig" }

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
select sink, source, sink, "Possible ReDoS vulnerability, the tainted data flows from here to a regular expression $@.", source.getNode(), ""

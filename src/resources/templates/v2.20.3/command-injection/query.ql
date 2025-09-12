/**
 *
 * @name Command injection
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @severity high
 * @kind path-problem
 * @precision high
 * @id js/command-line-injection
 * @tags external/cwe/cwe-088
 *
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.IndirectCommandArgument
import semmle.javascript.security.dataflow.CommandInjectionCustomizations::CommandInjection

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class Config extends TaintTracking::Configuration {
  Config() { this = "custom.CommandInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Function f | hasLocation(f) and source.asExpr().getEnclosingFunction() = f | {{SOURCE_PREDICATE}})
  }

  predicate extraLLMSink(DataFlow::Node sink) {
    {{EXTRA_SINK}}
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink
    or
    isIndirectCommandArgument(sink, _)
    or extraLLMSink(sink)
  }

}

import DataFlow::PathGraph

from Config dataflow, DataFlow::PathNode source, DataFlow::PathNode sink
where dataflow.hasFlowPath(source, sink)
select sink, source, sink, "This command depends on $@.", source.getNode(), ""

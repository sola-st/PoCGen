/**
 * @id query-ext-api-calls
 * @name Find all external API calls in the codebase.
 * @description Find all external API calls in the codebase.
 * @kind problem
 * @precision low
 * @problem.severity warning
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.ExternalAPIUsedWithUntrustedDataCustomizations

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class TaintStep extends Unit {
  abstract predicate step(DataFlow::Node fromNode, DataFlow::Node toNode);
}

class Config extends TaintTracking::Configuration {
  Config() { this = "custom.CommandInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Function f | hasLocation(f) and source.asExpr().getEnclosingFunction() = f | {{SOURCE_PREDICATE}})
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CallExpr ca | ca.getAnArgument() = sink.asExpr()) and
        (
          sink instanceof ExternalApiUsedWithUntrustedData::Sink
          or
          exists(CallExpr ca | ca.getAnArgument() = sink.asExpr() |
            not exists(FunctionDeclStmt v | ca.getReceiver() = v.getVariable().getAnAccess())
            /*
            not exists(DeclStmt v |
              ca.getReceiver() = v.getADecl().getBindingPattern().getAVariable().getAnAccess()
              or
              ca.getCallee() = v.getADecl().getBindingPattern().getAVariable().getAnAccess()
              or
              ca.getReceiver() = v.getADecl().getBindingPattern().getAVariable().getAReference()
            )*/

          )

        )
  }
}

from Config dataflow, DataFlow::PathNode source, DataFlow::PathNode sink, InvokeExpr ca
where
  dataflow.hasFlowPath(source, sink) and
  exists(CallExpr x | ca = x and ca.getAnArgument() = sink.getNode().asExpr())
select ca, ca.toString()

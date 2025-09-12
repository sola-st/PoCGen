/**
 *
 * @name Path Traversal
 * @description Using externally controlled strings to access files or directories can lead to path traversal vulnerabilities.
 * @severity high
 * @kind path-problem
 * @precision high
 * @id js/path-traversal
 * @tags external/cwe/cwe-22 external/cwe/cwe-23 external/cwe/cwe-36
 *
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.TaintedPathQuery

predicate hasLocation(Function f) {
  {{FUNCTION_PREDICATE}}
}

class FileReadNode extends DataFlow::Node {
  FileReadNode() { exists(FileReadCall f | this = f.getArgument(0)) }
}

class FileReadCall extends DataFlow::CallNode {
  string member;

  FileReadCall() {
    member =
      ["createReadStream", "open", "openSync", "read", "readSync", "readFile", "readFileSync"] and
    (
      this = NodeJSLib::FS::moduleMember(member).getACall()
      or
      // fs/promises
      this = NodeJSLib::FS::moduleMember("promises").getAMemberCall(member)
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "custom.PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Function f | hasLocation(f) and source.asExpr().getEnclosingFunction() = f | {{SOURCE_PREDICATE}})
    or extraSource(source)
  }

  predicate extraSource(DataFlow::Node source) {
      {{EXTRA_SOURCE}}
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileReadNode
    or extraSink(sink)
  }

  predicate extraSink(DataFlow::Node sink) {
      {{EXTRA_SINK}}
  }
}

import DataFlow::PathGraph

from Config dataflow, DataFlow::PathNode source, DataFlow::PathNode sink
where dataflow.hasFlowPath(source, sink)
select sink, source, sink, "The tainted data flows from here to a path traversal sink."

import { EventEmitter } from "events";

export class TSServerRequest {
  constructor(seq, command, args = null) {
    this.seq = seq;
    this.type = "request";
    this.command = command;
    this.arguments = args;
  }

  toString() {
    return (
      JSON.stringify({
        seq: this.seq,
        type: this.type,
        command: this.command,
        arguments: this.arguments,
      }) + "\n"
    );
  }

  toBytes() {
    return Buffer.from(this.toString(), "utf-8");
  }
}

export class TSServerOutputHandler {
  constructor(requestSeq) {
    this.requestSeq = requestSeq;
    this.outputBuffer = new EventEmitter();
  }

  push(outputBody) {
    this.outputBuffer.emit("data", outputBody);
  }

  async waitOutput() {
    return new Promise((resolve) => {
      this.outputBuffer.once("data", resolve);
    });
  }
}

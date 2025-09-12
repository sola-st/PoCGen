import { TSServerEvent } from "./TSServerEvent.js";
import { TSServerMessageParseException } from "./TSServerExceptions.js";

export class TSServerResponse {
  static fromBytes(buffer) {
    try {
      const body = JSON.parse(buffer.toString("utf-8"));
      if (body.type === "response") {
        return new TSServerResponse(body);
      } else if (body.type === "event") {
        return new TSServerEvent(body);
      } else {
        throw new TSServerMessageParseException();
      }
    } catch (error) {
      console.error(error);
      return null;
    }
  }

  constructor({ seq, command, request_seq, success, message, body, metadata }) {
    this.type = "response";
    this.seq = seq;
    this.command = command;
    this.request_seq = request_seq;
    this.success = success;
    this.message = message || null;
    this.body = body || null;
    this.metadata = metadata || null;
  }
}

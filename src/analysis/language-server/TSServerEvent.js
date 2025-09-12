export class TSServerEvent  {
  constructor({ seq, event, body }) {
      this.type = "event";
    this.seq = seq;
    this.event = event;
    this.body = body;
  }

  isRequestCompleted(reqSeq) {
    return (
      this.event === "requestCompleted" && this.body?.request_seq === reqSeq
    );
  }
}

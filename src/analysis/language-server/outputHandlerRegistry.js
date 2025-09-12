export class OutputHandlerRegistry {
    constructor() {
        this.responseHandlers = new Map();
        this.eventHandlers = new Map();
    }

    registerHandler(triggerBy, handler) {
        const {requestSeq} = handler;
        if (triggerBy === "response" || triggerBy === "all") {
            this.responseHandlers.set(requestSeq, handler);
        }
        if (triggerBy === "event" || triggerBy === "all") {
            this.eventHandlers.set(requestSeq, handler);
        }
    }

    deregisterHandler(handler) {
        const {requestSeq} = handler;
        this.responseHandlers.delete(requestSeq);
        this.eventHandlers.delete(requestSeq);
    }

    async onOutput(outputBody) {
        if (outputBody.type === "response") {
            const handler = this.responseHandlers.get(outputBody.request_seq);
            if (handler) {
                handler.push(outputBody);
            }
        } else if (outputBody.type === "event") {
            this.eventHandlers.forEach((handler) => handler.push(outputBody));
        } else {
            throw new Error(`Unknown Output Type: "${outputBody.type}"`);
        }
    }
}

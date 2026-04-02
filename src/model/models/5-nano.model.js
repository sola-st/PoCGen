import OpenAIModel from "../openai.js";

export const name = "gpt-5-nano";

export default class Gpt5NanoModel extends OpenAIModel {
   /** @inheritDoc */
   constructor(modelOptions) {
      super(name, { ...modelOptions, reasoning_effort: "minimal" });
   }
}

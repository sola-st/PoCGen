import OpenAIModel from "../openai.js";

export const name = "gpt-5-mini";

export default class Gpt5MiniModel extends OpenAIModel {
   /** @inheritDoc */
   constructor(modelOptions) {
      super(name, { ...modelOptions, reasoning_effort: "minimal" });
   }
}

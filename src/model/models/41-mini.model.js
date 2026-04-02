import OpenAIModel from "../openai.js";

export const name = "gpt-4.1-mini";

export default class Gpt41MiniModel extends OpenAIModel {
   /** @inheritDoc */
   constructor(modelOptions) {
      super(name, modelOptions);
   }
}

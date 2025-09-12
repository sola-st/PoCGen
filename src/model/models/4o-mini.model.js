import OpenAIModel from "../openai.js";

export const name = "gpt-4o-mini";

export default class Gpt4oMiniModel extends OpenAIModel {
   /** @inheritDoc */
   constructor(modelOptions) {
      super(name, modelOptions);
   }
}

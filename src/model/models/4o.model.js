import OpenAIModel from "../openai.js";

export const name = "gpt-4o";

export default class Gpt4oModel extends OpenAIModel {
   /** @inheritDoc */
   constructor(modelOptions) {
      super(name, modelOptions);
   }
}

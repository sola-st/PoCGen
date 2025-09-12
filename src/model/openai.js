import {OpenAI} from "openai";
import Model from "./model.js";
import {fnIndexes} from "./tools.js";

const REFUSAL = [
   "I'm sorry, I can't do that. Please try again.",
   "I can't assist with that",
];

/**
 * @typedef {import('openai/src/resources/chat/completions.ts').ChatCompletionTool} ChatCompletionTool
 */

/**
 * @typedef {import('./model.js').FunctionCall} FunctionCall
 */

export default class OpenAIModel extends Model {
   /**@inheritDoc */
   constructor(modelName, modelOptions) {
      super(modelName, modelOptions);
      this.openai = new OpenAI();
      this.contextLimit = 80_000;
   }

   /** @inheritDoc */
   wasRefused(response) {
      for (const refuse of REFUSAL) {
         if (response.toLowerCase().includes(refuse.toLowerCase())) {
            return true;
         }
      }
      return false;
   }

   /** @inheritDoc */
   async query(prompt, opts = undefined) {
      this.checkTokenExceeded();

      // Make sure the prompt does not exceed the maximum token limit
      const tokens = prompt.userPrompt.split(" ");
      if (tokens.length > this.contextLimit) {
         const result = tokens.slice(0, this.contextLimit).join(" ");
         console.warn(`Prompt exceeds token limit, truncating to ${this.contextLimit} tokens`);
         prompt.userPrompt = result;
      }

      let openaiOpts;
      if (opts) {
         openaiOpts = {
            temperature: opts.temperature ?? 1,
            n: opts.choices ?? 1,
            max_completion_tokens: opts.maxCompletionTokens,
            tools: opts.tools,
         };
      }
      const completion = await this.openai.chat.completions.create({
         ...openaiOpts,
         model: this.modelName,
         messages: [
            {
               role: "system",
               content: prompt.systemPrompt,
            },
            {
               role: "user",
               content: prompt.userPrompt,
            },
         ],
      });
      /*  this.promptTokens += completion.usage.prompt_tokens;
        this.completionTokens += completion.usage.completion_tokens;
  */
      let functionCalls = [], completions = [];
      for (const choice of completion.choices) {

         if (choice.finish_reason === "tool_calls") {
            const calls = choice.message.tool_calls;
            for (const call of calls) {
               functionCalls.push(
                  {
                     name: call.function.name,
                     arguments: JSON.parse(call.function.arguments),
                  }
               );
            }
         } else {
            completions.push(choice.message.content);
         }

      }
      /*   if (completion.choices[0]?.finish_reason === "tool_calls") {
            const calls = completion.choices
               .map((c) => c.message.tool_calls)
               .flat()
               .map((c) => c.function);

            functionCalls = [];
            for (const call of calls) {
               functionCalls.push(
                  {
                     name: call.name,
                     arguments: JSON.parse(call.arguments),
                  }
               );
            }
         }
      */   // return completion.choices.map((c) => c.message.content);
      // const completions = completion.choices.map((c) => c.message.content);
      return {
         completions,
         functionCalls,
         usage: {
            promptTokens: completion.usage.prompt_tokens,
            completionTokens: completion.usage.completion_tokens,
         }
      }
   }

   /** @inheritDoc */
   async queryTools(prompt, tools, opts = undefined) {
      const modelResponse = await this.query(prompt, {...opts, tools});

      const toolNames = tools.map((tool) => tool.function.name);

      /**
       * @type {FunctionCall[]}
       */
      const toolCalls = [];
      for (const call of modelResponse.functionCalls) {
         if (!toolNames.includes(call.name)) {
            throw new Error(`Unknown tool call "${call}"`);
         }
         if (!call.name || !call.arguments) {
            console.warn("Invalid tool call", call);
            continue;
         }
         toolCalls.push(call);
         /*toolCalls.push(
            {
               name: completion.name,
               args: JSON.parse(completion.arguments),
            }
         );*/
      }
      return toolCalls;
   }

   /** @inheritDoc */
   async queryIndexes(prompt, choices, opts = undefined) {
      const arrToolCalls = await this.queryTools(prompt, [fnIndexes], opts);
      const resultIndexes = [];
      for (const toolCall of arrToolCalls) {
         resultIndexes.push(...toolCall.args.indexes);
      }
      return Array.from(new Set(resultIndexes)).map((idx) => {
         if (idx < 0 || idx >= choices.length) {
            throw new Error(`Index out of bounds: ${idx}`);
         }
         return choices[idx];
      });
   }
}

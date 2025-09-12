import {isNumber, recListFiles, stripRecursively} from "../utils/utils.js";
import {join} from "node:path";

/**
 * @typedef {object} QueryOptions
 * @property {number} [temperature] - The temperature setting for the query.
 * @property {number} [choices] - The number of choices to return.
 * @property {number} [maxCompletionTokens] - The maximum number of completion tokens.
 * @property {ChatCompletionTool[]} [tools] - An array of tools to use for chat completions.
 */

/**
 * @typedef {object} ModelOptions
 * @property {number?} [maxCompletionTokensTotal] - The temperature setting for the query.
 * @property {number?} [maxPromptTokensTotal] - The temperature setting for the query.
 * @property {boolean?} [promptCache] - Cache the results of the model.
 */

/**
 * @typedef {object} FunctionCall
 * @property {string} [name] - The name of the function.
 * @property {object} [arguments] - The arguments of the function.
 */

/**
 * @typedef {Object} PromptUsage
 * @property {number} promptTokens - The number of prompt tokens.
 * @property {number} completionTokens - The number of completion tokens.
 */

/**
 * @typedef {Object} ModelResponse
 * @property {string[]} completions - The completions text.
 * @property {FunctionCall[]} functionCalls - The function calls.
 * @property {PromptUsage} usage - The usage statistics.
 */

export const None = "NONE";

export function isNone(str) {
   return (
      typeof str === "string" &&
      str.replace(/[^a-zA-Z0-9]/g, "").toLowerCase() === None.toLowerCase()
   );
}

/**
 * @returns {Promise<{name:string, default:Function}[]>}
 */
export async function loadModels() {
   const models = [];
   for (const name of recListFiles(join(import.meta.dirname, "models"))) {
      models.push(await import(name));
   }
   return models;
}

export class TokenLimitExceededError extends Error {
}

/**
 * Represents a language model for querying and processing prompts.
 */
export default class Model {

   /**
    * @type {PromptUsage}
    */
   cachedPromptsUsage = {
      promptTokens: 0,
      completionTokens: 0
   };

   /**
    * @type {PromptUsage}
    */
   uncachedPromptsUsage = {
      promptTokens: 0,
      completionTokens: 0
   };

   /**
    * The number of prompt tokens used so far.
    * @type {number}
    */
   get totalPromptTokens() {
      return this.cachedPromptsUsage.promptTokens + this.uncachedPromptsUsage.promptTokens;
   }

   /**
    * The number of completion tokens used so far.
    * @returns {number}
    */
   get totalCompletionTokens() {
      return this.cachedPromptsUsage.completionTokens + this.uncachedPromptsUsage.completionTokens;
   }

   /* /!**
     * The number of prompt tokens used so far.
     * @type {number}
     *!/
    promptTokens = 0;

    /!**
     * The number of completion tokens used so far.
     * @type {number}
     *!/
    completionTokens = 0;
 */
   /**
    * Creates an instance of the Model class.
    *
    * @param {string} modelName - The name of the model.
    * @param {ModelOptions?} options - The options for the model.
    */
   constructor(modelName, options) {
      this.modelName = modelName;
      this.modelOptions = options;
   }

   /**
    * Queries the model with the given prompt and returns the first result.
    *
    * @param {Prompt} prompt - The input prompt for the query.
    * @param {QueryOptions} [opts] - Additional options for the query (optional).
    * @returns {Promise<string>} - A promise that resolves to the first result of the query.
    */
   async queryOne(prompt, opts = undefined) {
      return (await this.query(prompt, opts)).completions[0];
   }

   /**
    * Queries the model with the given prompt and options.
    *
    * @param {Prompt} prompt - The input prompt for the query.
    * @param {QueryOptions?} opts - Additional options for the query (optional).
    * @returns {Promise<ModelResponse>} - A promise that resolves to the model response.
    */
   async query(prompt, opts = undefined) {
      throw new Error("Not implemented");
   }

   /**
    * Queries the model with the given prompt and tools.
    *
    * @param {Prompt} prompt - The input prompt for the query.
    * @param {ChatCompletionTool[]} tools - An array of tools to use for chat completions.
    * @param {QueryOptions?} [opts] - Additional options for the query (optional).
    * @returns {Promise<FunctionCall[]>} - A promise that resolves to a list of function calls.
    */
   async queryTools(prompt, tools, opts = undefined) {
      throw new Error("Not implemented");
   }

   /**
    * Was the response refused?
    * @param {string} response
    * @returns {boolean}
    */
   wasRefused(response) {
      throw new Error("Not implemented");
   }

   /**
    * @param prompt {Prompt}
    * @param choices {any[]}
    * @param opts {object}
    * @returns {Promise<*|string|null>} - null if response is invalid or model response is {@link isNone}
    */
   async queryIndex(prompt, choices, opts = undefined) {
      const response = stripRecursively(
         stripRecursively(
            stripRecursively((await this.queryOne(prompt, opts)).trim(), '"'),
            "'",
         ),
         "`",
      );
      if (typeof response !== "string") {
         throw new Error("Expected a string");
      }
      if (isNone(response)) {
         return null;
      }
      const parsedIdx = parseInt(response);
      if (isNaN(parsedIdx) || parsedIdx < 0 || parsedIdx >= choices.length) {
         console.warn(`Invalid index provided: "${parsedIdx}"`);
         return null;
      }
      return choices[parsedIdx];
   }

   /**
    * @param prompt {Prompt}
    * @param choices {any[]}
    * @param opts {QueryOptions}
    * @returns {Promise<Array<*>|null>} - null if response is invalid or model response is {@link isNone}
    */
   async queryIndexes(prompt, choices, opts = undefined) {
      const m = await this.queryOne(prompt, opts);
      const response = stripRecursively(
         stripRecursively(
            stripRecursively(m, '"'),
            "'",
         ),
         "`",
      );
      if (typeof response !== "string") {
         throw new Error("Expected a string");
      }
      if (isNone(response)) {
         return null;
      }
      const spl = response.split("\n")[0].split(/\s*,\s*/);
      const result = [];
      for (const idxStr of spl) {
         const parsedIdx = parseInt(idxStr);
         if (isNaN(parsedIdx) || parsedIdx < 0 || parsedIdx >= choices.length) {
            throw new Error(`Invalid index provided: "${idxStr}"`);
         }
         result.push(choices[parsedIdx]);
      }
      return result;
   }

   /**
    * @throws {TokenLimitExceededError}
    */
   checkTokenExceeded() {
      if (isNumber(this.modelOptions?.maxCompletionTokensTotal) && this.modelOptions.maxCompletionTokensTotal < this.totalCompletionTokens) {
         throw new TokenLimitExceededError(`Completion tokens exceeded: ${(this.totalCompletionTokens)} > ${this.modelOptions.maxCompletionTokensTotal}`);
      }
      if (isNumber(this.modelOptions?.maxPromptTokensTotal) && this.modelOptions.maxPromptTokensTotal < this.totalPromptTokens) {
         throw new TokenLimitExceededError(`Prompt tokens exceeded: ${(this.totalPromptTokens)} > ${this.modelOptions.maxPromptTokensTotal}`);
      }
      return false;
   }

   /**
    * Provide usage statistics related to the runner operation.
    */
   toJSON() {
      const {cachedPromptsUsage, uncachedPromptsUsage} = this;
      return {
         cachedPromptsUsage,
         uncachedPromptsUsage,
         totalPromptTokens: this.totalPromptTokens,
         totalCompletionTokens: this.totalCompletionTokens,
         modelName: this.modelName,
      };
   }
}

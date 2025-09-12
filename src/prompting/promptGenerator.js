import {esc, extractSourceCode, recListFiles, wrapBackticks, wrapTripleBackticks} from "../utils/utils.js";
import {Prompt} from "./prompt.js";
import * as fs from "node:fs";
import {join, relative} from "path";
//import * as handlebars from "handlebars";
import {default as handlebars} from "handlebars";
import {basename} from "node:path";

for (const fn of [esc, wrapTripleBackticks, wrapBackticks]) {
   handlebars.registerHelper(fn.name, fn);
}

handlebars.registerHelper("slice", (str, start, end) => str.slice(start, end));
handlebars.registerHelper("eq", (a, b) => a === b);
handlebars.registerHelper('concat', function (...args) {
   // Remove the last argument as it's the Handlebars options object
   args.pop();
   return args.join('');
});

const regFiles = [];
const baseDir = join(import.meta.dirname, "prompts");
recListFiles(baseDir, /.*\.hbs/, "filesOnly").forEach((absPath) => {
   handlebars.registerPartial(relative(baseDir, absPath.replace('.hbs', '')), fs.readFileSync(absPath, 'utf-8'));
   const name = basename(absPath).replace('.hbs', '');
   regFiles.push(name);
   handlebars.registerPartial(name, fs.readFileSync(absPath, 'utf-8'));
});

const fileCache = new Map();

export function renderTemplate(promptPath, vars) {
   if (!fileCache.has(promptPath)) {
      const fileContent = fs.readFileSync(promptPath, "utf-8");
      const template = handlebars.compile(fileContent,
         {
            noEscape: true,
            strict: true,
            preventIndent: true,
         });
      fileCache.set(promptPath, template);
   }
   try {
      return fileCache.get(promptPath)(vars, {
         allowProtoMethodsByDefault: true,
         allowProtoPropertiesByDefault: true,
      });
   } catch (e) {
      throw new Error(`Template ${promptPath}: ${e.message}`, {
         cause: e
      });
   }
}

/**
 * Retrieves the content of a prompt resource file, substitutes variables, and caches the result.
 *
 * @param {string} promptName - The name of the prompt resource file (without extension).
 * @param {{any:any}?} vars - An object containing variables to substitute in the prompt content.
 * @returns {Prompt} - The content of the prompt resource file with variables substituted.
 */
export function getPrompt(promptName, vars) {
   const userPrompt = renderPromptTemplate(`${promptName}.user`, vars);
   const sysPrompt = renderPromptTemplate(`${promptName}.system`, vars);
   return new Prompt(sysPrompt, userPrompt);
}

const promptDir = join(import.meta.dirname, "prompts");

/**
 * Retrieves the content of a prompt resource file, substitutes variables, and caches the result.
 *
 * @param {string} promptName - The name of the prompt resource file (without extension).
 * @param {{any:any}?} vars - An object containing variables to substitute in the prompt content.
 * @returns {string} - The content of the prompt resource file with variables substituted.
 */
export function renderPromptTemplate(promptName, vars) {
   const promptPath = join(import.meta.dirname, "prompts", `${promptName}.hbs`);
   return renderTemplate(promptPath, vars);
}

export default class PromptGenerator {
   /**
    * @param {Runner} runner
    */
   constructor(runner) {
      this.runner = runner;
   }

   /**
    * @param {Model} model
    * @param {VulnerabilityType} vulnerabilityType
    * @param {PotentialSinkList} potentialSinkList
    * @returns {Promise<TaintPath[]>}
    */
   async getPromptIdentifySinks(model, vulnerabilityType, potentialSinkList) {
      const toolReturnSinks = {
         type: "function",
         function: {
            name: "returnSinks",
            description: `Use this function to return the identified ${vulnerabilityType.label} sinks`,
            strict: true,
            parameters: {
               type: "object",
               properties: {
                  index: {
                     type: "number",
                     description: `The index of the function that is a ${vulnerabilityType.label} sink`,
                  },
                  reason: {
                     type: "string",
                     description: `The reason why the function is a ${vulnerabilityType.label} sink`,
                  }
               },
               required: ["index", "reason"],
               additionalProperties: false,
            },
         },
      }
      let idx = 0;
      let snippets = [];
      for (const potentialSinks of potentialSinkList.entries) {
         let curSnippet = "";
         if (potentialSinks.location.filePath.startsWith("/")) {
            curSnippet += `${idx++}: ${extractSourceCode(potentialSinks.location, fs.readFileSync(potentialSinks.location.filePath, "utf-8"))}\n`;
         } else {
            curSnippet += `${idx++}: ${this.runner.codeQL.extractSourceCode(potentialSinks.location)}\n`;
         }
         curSnippet += `Calls:\n`;
         curSnippet += "```js\n";
         for (const message of Array.from(
            new Set(potentialSinks.potentialSinks.map((sink) => sink.message)),
         ).slice(0, 5)) {
            curSnippet += `${message}\n`;
         }
         curSnippet += "```\n";
         snippets.push(curSnippet);
      }
      let examples = "";
      try {
         examples = fs.readFileSync(join(promptDir, "identifySinks", `${vulnerabilityType.label}.md`), "utf-8");
      } catch (e) {
         console.log(`No examples found for ${vulnerabilityType.label}`);
      }

      const sysPrompt = renderPromptTemplate(`identifySinks/system`,
         {
            vulnerabilityType: vulnerabilityType,
            toolName: toolReturnSinks.function.name,
            examples
         });

      const prompt = new Prompt(sysPrompt, snippets.join("\n"));
      const resultIndexes = (await model.queryTools(
         prompt,
         [toolReturnSinks],
      )).map((t) => t.arguments.index);
      return Array.from(new Set(resultIndexes)).map((idx) => {
         if (idx < 0 || idx >= potentialSinkList.entries.length) {
            console.warn(`Index out of bounds: ${idx}`);
            return null;
         }
         return potentialSinkList.entries[idx];
      }).filter(s => s).flatMap((potentialSinks) => potentialSinks.taintPaths);

   }

}


import {
   esc,
   firstNonEmpty,
   joinAccessIdentifiers,
   wrapBackticks,
   wrapInExploitFunction,
   wrapTripleBackticks,
} from "../utils/utils.js";
import CodeGenerator from "../prompting/codeGenerator.js";

/**
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("../../models/locationRange").default} LocationRange
 */
export default class Source {

   /**
    * List of snippets that can be used to call the callable
    * @type {string[]}
    */
   snippets = [];

   /**
    * @param {(ApiNode|ApiFunction)[]} parentChain - An array representing the chain of parent objects leading to the callable
    * @param {ApiFunction} callable - The actual callable object
    * @param {ApiModule} module - The name of the module where the callable is defined
    * @param {boolean} isGlobal - Indicates whether the callable is defined in the global scope.
    * @param {boolean} isExported - Indicates whether the callable is exported.
    * @param {string} context - The context in which the callable is defined.
    */
   constructor(
      parentChain,
      callable,
      module,
      isGlobal,
      isExported,
      context = undefined,
   ) {
      this.parentChain = parentChain;
      this.callable = callable;
      this.module = module;
      this.isGlobal = isGlobal;
      this.isExported = isExported;
      this.type = callable.type;
   }

   /**
    * @returns {ApiFunction|undefined}
    */
   getParentClass() {
      return this.parentChain.find((c) =>
         isClass(c) &&
         c.protoFunctions.some((pf) => pf.location === this.callable.location)
      );
   }

   /**
    * @returns {ApiFunction|null}
    */
   getConstructor() {
      const parentClass = this.getParentClass();
      if (!parentClass) {
         return null;
      }
      if (this.type === "ClassMethod") {
         return parentClass.protoFunctions.find(
            (pf) => pf.kind === "constructor",
         );
      }
      return parentClass;
   }

   get apiCompletion() {
      const c = new CodeGenerator(this, false).generate().join(";\n");
      let prompt = "You can complete the following code snippet:\n";
      prompt += `${wrapTripleBackticks(wrapInExploitFunction(c), "js")}`;
      return prompt;
   }

   get name() {
      return firstNonEmpty(
         this.callable.exportName,
         this.callable.name,
         "anonymous",
      );
   }

   get qualifiedName() {
      if (this.parentChain.length === 0) {
         // Top level callable
         return firstNonEmpty(
            this.callable.exportName,
            this.callable.name,
            "default",
         )
      }
      return joinAccessIdentifiers(
         ...this.parentChain.map((x) => x.exportName),
         this.callable.exportName,
      );
   }

   get stringified() {
      return `${wrapBackticks(this.qualifiedName)} with signature: ${wrapBackticks(this.callable.signature)}`;
   }

   get toLLM() {
      const parentClass = this.getParentClass();
      const isConstructor = this.callable.kind === "constructor";

      let sourceName = this.qualifiedName; /*firstNonEmpty(
         this.callable.name,
         this.callable.exportName,
      );*/
      if (sourceName) {
         sourceName = `${parentClass ? "method" : "function"} ${wrapBackticks(sourceName)}`;
      } else {
         sourceName = `anonymous function with signature ${wrapBackticks(this.callable.signature)}`;
      }
      if (this.callable.isModuleRoot) {
         sourceName += ` default export of module ${esc(this.module.importName)}`;
      }
      let result;
      if (isConstructor) {
         result = `constructor of class ${esc(parentClass.name)}`;
      } else {
         if (
            this.callable.name?.length > 0 &&
            this.callable.exportName?.length > 0 &&
            this.callable.name !== this.callable.exportName
         ) {
            sourceName = `${sourceName} (exported as ${wrapBackticks(this.callable.exportName)})`;
         }
         if (parentClass) {
            result = `${sourceName} of class ${esc(parentClass.name)}`;
         } else {
            result = `${sourceName}`;
         }
      }
      return result;
   }

   /**
    * @returns {ApiFunction|undefined}
    */
   getParentClass() {
      return this.parentChain.find((c) => {
         return (
            isClass(c) &&
            c.protoFunctions.some(
               (pf) => pf.location === this.callable.location,
            )
         );
      });
   }

   isClass() {
      return isClass(this.callable);
   }

   /**
    * @returns {string|undefined}
    */
   getFullExportName() {
      return joinAccessIdentifiers(
         ...this.parentChain.map((x) => x.exportName),
         this.callable.exportName,
      );
   }

   toString() {
      return JSON.stringify(
         firstNonEmpty(
            this.getFullExportName(),
            this.stringified,
            `anonymous function ${JSON.stringify(this.callable.signature)}`,
         ),
      );
   }

   serializeForStatUsage() {
      return {
         stringified: this.stringified,
         callable: {
            exportName: this.callable.exportName,
            name: this.callable.name,
            type: this.callable.type,
            location: this.callable.location,
         },
      };
   }

   toJSON() {
      // Dont store module.exports
      const {exports, ...moduleInfo} = this.module;
      return {
         stringified: this.stringified,
         callable: this.callable,
         module: moduleInfo,
         isGlobal: this.isGlobal,
         isExported: this.isExported,
      };
   }
}

/**
 * @param {ApiNode|ApiFunction} apiNode
 * @returns {boolean}
 */
function isClass(apiNode) {
   return apiNode.protoFunctions?.length > 0 ||
      apiNode.callable?.protoFunctions?.length > 0 ||
      apiNode.type === "ClassDeclaration" ||
      apiNode.type === "ClassExpression"
}


import {firstNonEmpty, getIdentifierName, joinAccessIdentifiers} from "../utils/utils.js";
import LocationRange from "../models/locationRange.js";

const completeThis = "..."; // "[complete this]";

export default class CodeGenerator {
   /**
    * List of variables used in the exploit code
    * @type {string[]}
    */
   usedIdentifiers = [];

   /**
    * @type {string[]}
    */
   codeLines = [];

   /**
    * @param {Source} source
    * @param {boolean} accessChainWithRequire
    */
   constructor(source, accessChainWithRequire) {
      this.source = source;
      this.accessChainWithRequire = accessChainWithRequire;
   }

   /**
    * Given a source object, generate the code for calling it
    * @returns {string[]}
    */
   generate() {
      this.doGenerate();
      return this.codeLines;
   }

   /**
    * Generate the code for calling the source object
    */
   doGenerate() {
      this.codeLines = [];
      const isConstructorCall = this.source.isClass();
      let requireStmt;
      if (this.source.module.isESM) {
         requireStmt = `await import(${JSON.stringify(this.source.module.importName)})`;
      } else {
         requireStmt = `require(${JSON.stringify(this.source.module.importName)})`;
      }
      // Class that needs to be instantiated for the method
      const parentClass = this.source.getParentClass();

      const moduleIdAccessChain = [];
      const requireAccessChain = [];

      let moduleId;
      if (this.source.isGlobal) {
         moduleId = "global";
         // Add comment to indicate that source is exported to global
         this.codeLines.push(
            `${requireStmt} // adds ${(this.source.toLLM)} to global scope`,
         );
      } else {
         if (this.source.callable.isModuleRoot) {
            // Extra case: module.exports = function() { ... }
            // Use function name as module id to prevent LLM from hallucinating
            moduleId = this.getUnusedIdentifier(firstNonEmpty(this.source.callable.exportName, this.source.callable.name, this.source.module.importName));
         } else if (parentClass?.isModuleRoot) {
            moduleId = this.getUnusedIdentifier(parentClass.name);
         } else if (this.accessChainWithRequire) {
            // Add the access chain after the require statement
            if (parentClass) {
               for (let parent of this.source.parentChain) {
                  if (parent === parentClass) {
                     requireAccessChain.push(parentClass.exportName);
                     moduleId = this.getUnusedIdentifier(parentClass.name);
                     break;
                  }
                  requireAccessChain.push(parent.exportName);
               }
            } else {
               requireAccessChain.push(...this.source.parentChain.map((p) => p.exportName));
               requireAccessChain.push(this.source.callable.exportName);
               moduleId = this.getUnusedIdentifier(firstNonEmpty(this.source.callable.name, this.source.callable.exportName));
            }
            if (requireAccessChain.length > 0) {
               requireStmt = `${requireStmt}.${joinAccessIdentifiers(...requireAccessChain)}`;
            }
            const childMatch = this.source.parentChain[0]?.children?.find(s => LocationRange.equals(s.location, this.source.callable.location));
            if (childMatch && childMatch.name !== childMatch.exportName && childMatch.name.length > 0 && childMatch.exportName.length > 0) {
               // Extra case: if name does not match `exportName`, use `exportName` as moduleId to prevent LLM from hallucinating
               moduleId = this.getUnusedIdentifier(this.source.callable.name);
            }
         } else {
            if (parentClass) {
               for (let parent of this.source.parentChain) {
                  if (parent === parentClass) {
                     moduleIdAccessChain.push(parentClass.exportName);
                     break;
                  }
                  moduleIdAccessChain.push(parent.exportName);
               }
            } else {
               moduleIdAccessChain.push(...this.source.parentChain.map((p) => p.exportName));
               moduleIdAccessChain.push(this.source.callable.exportName);
            }
            moduleId = this.getUnusedIdentifier(this.source.module.importName);
         }
         this.codeLines.push(`const ${moduleId} = ${requireStmt}`);
      }

      if (!(this.source.isGlobal || this.source.isExported)) {
         return;
      }

      const callAccessChain = [];
      let objectId;
      if (parentClass) {
         objectId = this.getObjectId(
            firstNonEmpty(parentClass.name, parentClass.exportName) + "Object",
         );
         const clsChain = [moduleId, ...moduleIdAccessChain];
         if (this.source.isGlobal) {
            clsChain.push(...this.source.parentChain.map((p) => p.exportName));
         }
         const objectCreation = `const ${objectId} = ${parentClass.isAsync ? "await " : ""}new ${joinAccessIdentifiers(...clsChain)}(${completeThis})`;
         this.codeLines.push(objectCreation);
         callAccessChain.push(objectId);
         callAccessChain.push(this.source.callable.exportName);
      } else {
         callAccessChain.push(moduleId, ...moduleIdAccessChain);
         if (this.source.isGlobal) {
            callAccessChain.push(...this.source.parentChain.map((p) => p.exportName));
            callAccessChain.push(this.source.callable.exportName);
         }
      }

      let callStmt;
      switch (this.source.callable.kind) {
         case "constructor":
            break;
         case "get":
            callStmt = `const result = await${isConstructorCall ? " new" : ""} ${joinAccessIdentifiers(...callAccessChain)} // trigger getter`;
            break;
         case "set":
            callStmt = `${joinAccessIdentifiers(...callAccessChain)} = ${completeThis} // trigger setter`;
            break;
         default:
            callStmt = `const result = await${isConstructorCall ? " new" : ""} ${joinAccessIdentifiers(...callAccessChain)}(${completeThis})`;
            break;
      }
      this.codeLines.push(callStmt);
   }

   /**
    * Lowercase the first letter of a string, if equals then append "Object"
    * @param {string} className - Non-empty string
    */
   getObjectId(className) {
      if (className.length === 0) {
         throw new Error("Class name cannot be empty");
      }
      const id =
         className[0].toLowerCase() === className[0]
            ? className + "Object"
            : className // className[0].toLowerCase() + className.slice(1);
      return this.getUnusedIdentifier(id);
   }

   /**
    * Get a valid identifier that is not already in use
    * @param {string} name
    * @returns {string|null} - A valid identifier that is not already in use
    */
   getUnusedIdentifier(name) {
      if (!name) return null;
      let id = getIdentifierName(name);
      let i = 0;
      while (this.usedIdentifiers.includes(id)) {
         id = `${id}${i}`;
      }
      if (id.length === 0) {
         id = `var${this.usedIdentifiers.length}`;
      }
      this.usedIdentifiers.push(id);
      return id;
   }
}



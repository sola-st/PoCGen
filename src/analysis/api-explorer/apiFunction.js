import {getSignature, parseFunction} from "../../utils/parserUtils.js";
import ApiNode from "./apiNode.js";

export function isNativeFunction(code) {
   return !!code.match(/function\s*\w*\s*\(\)\s*\{\s*\[native code\]\s*\}/);
}

/**
 * @typedef {import("../../models/locationRange").default} LocationRange
 * @typedef {import("@babel/traverse").Node} Node
 *
 * An API node representing a function.
 * @extends {ApiNode}
 */
export default class ApiFunction extends ApiNode {

   /**
    * The kind of the API function.
    *
    * @type {"get" | "set" | "method" | "constructor"}
    */
   kind;

   /**
    * The signature of the API function.
    *
    * @type {string}
    */
   signature;

   /**
    * Creates an instance of ApiFunction.
    *
    * @param {string} code - The code of the function.
    * @param {string} name - The name of the function.
    * @param {LocationRange} location - The location range of the function.
    * @param {string?} [exportName] - The export name of the function.
    * @param {Node} [node] - The AST node of the function.
    * @param {ApiFunction[]} [protoFunctions] - The prototype functions.
    * @throws {Error} - If the function cannot be parsed.
    */
   constructor(
      code,
      name,
      location,
      exportName = undefined,
      node = undefined,
      protoFunctions = undefined,
   ) {
      super(exportName, [])
      this.code = code;
      this.name = name;
      this.location = location;
      this.isNative = isNativeFunction(code);
      if (node) {
         this.setNode(node);
      } else if (!this.isNative) {
         const parsedMethodNode = parseFunction(code);
         this.setNode(parsedMethodNode);
      }
      this.protoFunctions = protoFunctions;
   }

   /**
    * @param {Node} newNode
    */
   setNode(newNode = undefined) {
      if (!this.node) {
         if (newNode) {
            this.node = newNode;
         } else {
            this.node = parseFunction(this.code);
            const isExpression = this.node.type === "ExpressionStatement";
            if (isExpression) {
               this.node = this.node.expression;
            }
         }
      } else if (newNode) {
         this.node = newNode;
      }
      this.type = this.node.type;
      this.kind = this.node.kind;
      this.isAsync = this.node.async;
      this.signature = getSignature(this.node, this.code);
   }

   clone() {
      const copy = new ApiFunction(this.code, this.name, this.location);
      for (const attr in this) {
         if (this.hasOwnProperty(attr)) copy[attr] = this[attr];
      }
      return copy;
   }

   copyExportName(exportName) {
      if (exportName) {
         this.exportName = exportName;
      }
      const copy = this.clone();
      copy.exportName = exportName;
      return copy;
   }

   toJSON() {
      if (!this.node) {
         try {
            this.setNode();
         } catch (e) {
            console.error(e);
         }
      }
      return {
         ...super.toJSON(),
         name: this.name,
         signature: this.signature,
         isAsync: this.isAsync,
         moduleName: this.moduleName,
         location: this.location,
         code: this.code,
         type: this.type,
         kind: this.kind,
         protoFunctions: this.protoFunctions,
      };
   }

}

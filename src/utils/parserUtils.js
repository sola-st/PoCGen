import parser, { parse } from "@babel/parser";
import traverse from "@babel/traverse";
import generate from "@babel/generator";
import formatCode from "../runners/prettierFormat.js";
import LocationRange from "../models/locationRange.js";
import { esc, firstNonEmpty } from "./utils.js";

/**
 * @typedef {import("@babel/parser").ParserOptions} ParserOptions
 * @typedef {import("@babel/parser").ParseResult} ParseResult
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("../../models/locationRange").default} LocationRange
 * @typedef {import("@babel/types").File} BabelFile
 */

/**
 * Returns the name of the identifier from a Babel AST node.
 *
 * @param {Node} node - The Babel AST node to extract the identifier name from.
 */
export function getBabelNodeIdentifierName(node) {
   if (!node)
      return node;
   if (node.type === "AssignmentExpression") {
      return getBabelNodeIdentifierName(node.left);
   }

   return firstNonEmpty(node.id?.name, node.key?.name, node.key?.name, node.property?.name);
}

/**
 * Tries to parse the given code using Babel parser.
 * If parsing fails, it tries to parse it again with error recovery enabled.
 *
 * @param {string} code - The code to parse.
 * @returns {ParseResult<File>} - The parsed AST.
 */
export function doParse(code) {
   try {
      return parser.parse(code, {
         plugins: ["typescript", "jsx"],
         sourceType: "module",
      });
   } catch (e) {
      return parser.parse(code, {
         errorRecovery: true,
         plugins: ["typescript", "jsx"],
         sourceType: "module",
      });
   }
}

/**
 * Given a Babel AST and a location range, return the enclosing statement.
 *
 * @param {ParseResult<BabelFile>} ast - The Babel AST to search for the enclosing statement.
 * @param {LocationRange} locationRange - The location range to search for.
 * @returns {NodePath} - The enclosing statement NodePath.
 */
export function getEnclosingStatement(ast, locationRange) {
   let result;
   traverse.default(ast, {
      Program(path) {
         path.get("body").forEach((stmt) => {
            if (!result) {
               const location = LocationRange.fromBabelNode(stmt.node);
               if (location.contains(locationRange)) {
                  result = stmt;
                  path.stop();
               }
            }
         });
      },
   });
   return result;
}

/**
 * Given a Babel AST, return all the call expressions and constructor calls.
 *
 * @param {ParseResult<BabelFile>} ast - The Babel AST to search for call expressions.
 * @returns {Node[]} - An array of Node objects representing the call expressions found in the AST.
 */
export function getCallExpressionNodes(ast) {
   const callExpressions = [];
   traverse.default(ast, {
      CallExpression(path) {
         callExpressions.push(path.node);
      },
      // Also include new expressions
      NewExpression(path) {
         callExpressions.push(path.node);
      },
   });
   return callExpressions;
}

/**
 * Given a Babel AST, return all the call expressions.
 *
 * @param {ParseResult<BabelFile>} ast - The Babel AST to search for call expressions.
 * @returns {NodePath[]} - An array of NodePath objects representing the call expressions found in the AST.
 */
export function getAllCalls(ast) {
   const allCalls = [];
   traverse.default(ast, {
      CallExpression(path) {
         allCalls.push(path);
      },
   });
   return allCalls;
}

/**
 * Given a Babel AST, return all the function declarations and expressions.
 *
 * @param {ParseResult<BabelFile>} ast - The Babel AST to search for functions.
 * @returns {NodePath[]} - An array of NodePath objects representing the functions found in the AST.
 */
export function getAllFunctions(ast) {
   const allFunctions = [];
   traverse.default(ast, {
      Function(path) {
         allFunctions.push(path);
      },
   });
   return allFunctions;
}

/**
 * Given a Babel AST, return all the class methods.
 *
 * @param {ParseResult<BabelFile>} ast - The Babel AST to search for class methods.
 * @returns {NodePath[]} - An array of NodePath objects representing the class methods found in the AST.
 */
export function extractClassMethods(ast) {
   const classes = [];
   traverse.default(ast, {
      ClassMethod(path) {
         classes.push(path);
      },
   });
   return classes;
}

/**
 * Removes source URL comments from the given code.
 *
 * @param {string} code - The code to remove source URL comments from.
 * @returns {Promise<string>} - The code with source URL comments removed.
 */
export async function removeSourceURLComments(code) {
   const ast = parse(code, {
      plugins: ["typescript", "jsx"],
      sourceType: "module",
      errorRecovery: true,
   });

   traverse.default(ast, {
      enter(path) {
         if (path.node.leadingComments) {
            path.node.leadingComments = path.node.leadingComments.filter(
               (comment) => !comment.value.trim().match(/^#\s*source/),
            );
         }
         if (path.node.trailingComments) {
            path.node.trailingComments = path.node.trailingComments.filter(
               (comment) => !comment.value.trim().match(/^#\s*source/),
            );
         }
      },
   });
   const output = generate.default(
      ast,
      {
         minified: false,
      },
      code,
   );
   return await formatCode(output.code);
}

/**
 * Given a code string, parse it as a function.
 *
 * @param {string} code - The code to parse.
 * @returns {Node} - The parsed function AST node.
 */
export function parseFunction(code) {
   try {
      return parser.parseExpression(code, {
         errorRecovery: true,
      });
   } catch (e) {
      try {
         const objectExpression = parser.parseExpression(`{ ${code} }`, {
            errorRecovery: true,
         });
         const result = objectExpression.properties[0];
         if (result.type === "ObjectMethod") {
            return result;
         }
      } catch {
         try {
            return parser.parseExpression(`function ${code}`, {
               errorRecovery: true,
            });
         } catch {
            throw new Error(`Error parsing function: ${esc(code)}, error: ${e}`);
         }
      }
   }
}

/**
 * Extracts the function signature from a given AST node.
 *
 * @param {Node} node - The AST node representing the function.
 * @param {string} code - The original code string.
 * @returns {string} - The extracted function signature.
 */
export function getSignature(node, code) {
   let signature;
   try {
      switch (node.type) {
         case "CallExpression":
            signature = code.slice(0, node.end);
            break;
         case "ArrowFunctionExpression":
            signature = code.slice(0, node.body.start - node.start).trim();
            if (signature.endsWith("=>")) {
               signature += " {}";
            }
            break;
         default:
            if (node.kind === "constructor") {
               signature = code.slice(node.start, node.body.start);
            } else {
               signature = code.slice(0, node.body.start - node.start);
            }
            break;
      }
   } catch (e) {
      console.error(e);
   }
   // Fall back
   if (!signature) {
      signature = code.split("{", 2)[0];
   }
   return signature.trim();
}

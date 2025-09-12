export const possibleFiles = {
   type: "function",
   function: {
      name: "possibleFiles",
      description: "Called when a file is found",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            files: {
               type: "array",
               items: {
                  type: "string",
               },
               description: "List of files in which the vulnerable function is likely to be found",
            },
         },
         required: ["files"],
         additionalProperties: false,
      },
   },
};
export const onFoundSource = {
   type: "function",
   function: {
      name: "onFoundSource",
      description: "Called when the vulnerable function was identified",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            startLine: {
               type: "number",
               description: "The line number where the body of the vulnerable function was found.",
            },
            startColumn: {
               type: "number",
               description: "The column number where the body of the vulnerable function starts.",
            },
         },
         required: ["startLine", "startColumn"],
         additionalProperties: false,
      },
   },
};

export const findFunctionReferences = {
   type: "function",
   function: {
      name: "findFunctionReferences",
      description: "Find references to a function in the codebase",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            functionName: {
               type: "string",
               description: "The name of the function to find references to",
            },
         },
         required: ["functionName"],
         additionalProperties: false,
      },
   },
};

function findReferences(fileNames, functionName) {
   const program = ts.createProgram(fileNames, {});
   const checker = program.getTypeChecker();

   const references = [];

   for (const sourceFile of program.getSourceFiles()) {
      if (!sourceFile.isDeclarationFile) {
         ts.forEachChild(sourceFile, function visit(node) {
            if (
               ts.isIdentifier(node) &&
               node.text === functionName &&
               checker.getSymbolAtLocation(node)
            ) {
               references.push({
                  file: sourceFile.fileName,
                  loc: node.getSourceFile().getLineAndCharacterOfPosition(node.pos),
               });
            }
            ts.forEachChild(node, visit);
         });
      }
   }

   return references;
}

export const sortedIndexes = {
   type: "function",
   function: {
      name: "sortedIndexes",
      description: "Use this function to return the sorted indexes",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            indexes: {
               type: "array",
               items: {
                  type: "number",
               },
               description: "The sorted list of all indexes",
            },
         },
         required: ["indexes"],
         additionalProperties: false,
      },
   },
};

export const fnIndexes = {
   type: "function",
   function: {
      name: "returnIndexes",
      description: "Use this function to return the indexes",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            indexes: {
               type: "array",
               items: {
                  type: "number",
               },
               description: "The list of indexes",
            },
         },
         required: ["indexes"],
         additionalProperties: false,
      },
   },
};

export const fnIndexesUsage = `use the tool ${fnIndexes.function.name} to return the indexes`;

export const missingDefinitionTool = {
   type: "function",
   function: {
      name: "missingDefinition",
      description: "Called when a snippet references a missing definition that is relevant to the vulnerability",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            referenceLineNumber: {
               type: "number",
               description: "The line number where the missing definition is referenced.",
            },
            identifierName: {
               type: "string",
               description: "The fully qualified name of the function/ variable. That is if there is a member expression a.b.c(), respond with a.b.c",
            },
         },
         required: ["referenceLineNumber", "identifierName"],
         additionalProperties: false,
      },
   },
};

export const toolSortCandidates = {
   type: "function",
   function: {
      name: "functions",
      description: "Invoked after you have ranked the functions according to their susceptibility to the vulnerability",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            indexes: {
               type: "array",
               items: {
                  type: "number",
               },
               description: "The indexes of the functions sorted by relevance",
            },
         },
         required: ["indexes"],
         additionalProperties: false,
      },
   },
};

export const debugRequestsTool = {
   type: "function",
   function: {
      name: "debugExpressions",
      description: "Called to get values of expressions at runtime",
      strict: true,
      parameters: {
         type: "object",
         properties: {
            lineNumber: {
               "type": "integer",
               "description": "The line number of the expression"
            },
            expression: {
               "type": "string",
               "description": "A mathematical expression to evaluate"
            },
         },
         required: ["lineNumber", "expression"],
         additionalProperties: false,
      },
   },
};



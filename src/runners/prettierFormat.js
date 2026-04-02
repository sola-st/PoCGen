import * as prettier from "prettier";

/**
 * @param {string} code
 * @returns {Promise<string>}
 */
export default async function formatCode(code) {
   const options = {
      parser: "babel",       // Handles modern ES7+ syntax
      semi: false,           // Matches "semi": "never"
      tabWidth: 3,           // Matches "indent": 3
      bracketSpacing: true,  // Matches your prettierOptions
      singleQuote: false,    // Matches your fallbackPrettierOptions
      trailingComma: "es5",  // Recommended default for clean diffs
   };

   return await prettier.format(code, options);
}
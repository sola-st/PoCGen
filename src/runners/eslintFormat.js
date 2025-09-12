import format from "prettier-eslint";

/**
 * @param {string} code
 * @returns {Promise<string>}
 */
export default async function formatEsLint(code) {
   const options = {
      text: code,
      eslintConfig: {
         parserOptions: {
            ecmaVersion: 7
         },
         rules: {
            semi: ['error', 'never'],
            "newline-per-chained-call": ["error", {ignoreChainWithDepth: 1}],
            curly: ['error', 'all'],
            // Add newlines after blocks
            "brace-style": ["error", "1tbs", {"allowSingleLine": false}],
            // Ternary expressions should be on new lines
            "multiline-ternary": ["error", "always"],
            // 3 spaces for indentation
            indent: ["error", 3],
            // remove sourceURL
            "no-warning-comments": ["error", {terms: ["todo", "fixme", "any other term"], location: "anywhere"}],
         }
      },
      prettierOptions: {
         bracketSpacing: true
      },
      fallbackPrettierOptions: {
         singleQuote: false
      },
   };
   return await format(options);
}

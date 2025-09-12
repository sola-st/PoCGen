/**
 * @typedef {import("./declaration").default} Declaration
 */

export default class MissingDeclarations {
   /**
    * @type {MissingDeclarationsSnippet[]}
    */
   #declarations = [];

   /**
    * @param {FunctionSnippet} functionSnippet
    * @returns {MissingDeclarationsSnippet|null}
    */
   get(functionSnippet) {
      return this.#declarations.find((declaration) => declaration.functionSnippet === functionSnippet);
   }

   /**
    * Adds a new `MissingDeclarationsSnippet` to the list of declarations.
    *
    * @param {MissingDeclarationsSnippet} missingDeclarationsSnippet - The missing declarations snippet to add.
    */
   put(missingDeclarationsSnippet) {
      this.#declarations.push(missingDeclarationsSnippet);
   }

}

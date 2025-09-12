/**
 * @typedef {import("./declaration").default} Declaration
 */
import Declaration from "./declaration.js";

export default class MissingDeclarationsSnippet {
   /**
    * Store all declarations that were resolved.
    *
    * @type {Object.<string, Declaration>}
    */
   declarations = {};

   /**
    * @type {FunctionSnippet}
    */
   functionSnippet;

   /* /!**
     * @type {{[key: number]: Declaration[]}}
     *!/
    #declarations = {};*/

   /**
    * Constructs an instance of MissingDeclarationsSnippet.
    *
    * @param {FunctionSnippet} functionSnippet - The function snippet associated with the declarations.
    */
   constructor(functionSnippet) {
      this.functionSnippet = functionSnippet;
   }

   /**
    * Add a resolved declaration
    * @param {string} identifierName
    * @param {Location} referenceLocation
    * @param {Location[]} declarationLocations
    */
   addDeclaration(identifierName, referenceLocation, declarationLocations) {
      this.declarations[referenceLocation.toString()] = new Declaration(
         referenceLocation,
         identifierName,
         declarationLocations
      );
   }

   /**
    * @param {Location} referenceLocation
    * @returns {boolean}
    */
   hasDeclaration(referenceLocation) {
      return referenceLocation.toString() in this.declarations;
   }
}

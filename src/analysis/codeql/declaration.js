/**
 * Class representing a declaration.
 */
export default class Declaration {

   /**
    * Create a declaration.
    * @param {LocationRange} referenceLocation - The location of the reference.
    * @param {string} identifierName - The name of the identifier.
    * @param {LocationRange[]} locations - The locations of the declaration.
    */
   constructor(referenceLocation, identifierName, locations) {
      this.referenceLocation = referenceLocation;
      this.identifierName = identifierName;
      this.locations = locations;
   }
}

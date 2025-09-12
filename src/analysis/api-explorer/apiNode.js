/**
 * Base class that represents a node in the API structure.
 * @class
 */
export default class ApiNode {

   /**
    * Creates an instance of ApiNode.
    * @param {string} exportName - The name of the export.
    * @param {ApiNode[]} children - The child nodes of this API node.
    * @param {boolean} [isModuleRoot=false] - Whether this node is the root of a module.
    */
   constructor(exportName, children, isModuleRoot = false) {
      this.exportName = exportName;
      this.children = children;
      this.isModuleRoot = isModuleRoot;
   }

   /**
    * Converts the API node to a JSON representation.
    * @returns {Object} The JSON representation of the API node.
    */
   toJSON() {
      return {
         exportName: this.exportName,
         ...(this.children && {children: this.children}),
         isModuleRoot: this.isModuleRoot
      }
   }
}

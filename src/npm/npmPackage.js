/**
 * Represents an NPM package.
 *
 * @class
 */
export class NpmPackage {
   /**
    * Creates an instance of NpmPackage.
    *
    * @param {string} raw - The raw package string.
    * @param {string} name - The name of the package.
    * @param {string} version - The version of the package.
    * @param {string} [scope] - The scope of the package (optional).
    */
   constructor(raw, name, version, scope) {
      this.raw = raw;
      this.name = name;
      this.version = version;
      this.scope = scope;
   }

   asPath() {
      return (this.scope ? "@" + this.scope + "/" : "") + this.name;
   }

   asPathN() {
      return ((this.scope ? this.scope + "/" : "") + this.name).replaceAll(
         "@",
         "_",
      );
   }

   toPath() {
      return ((this.scope ? this.scope + "@" : "") + this.name).replaceAll(
         "/",
         "_",
      );
   }

   toString() {
      return this.raw;
   }

   // handle scoped package names such as @vendure/asset-server-plugin@2.3.2 => @vendure/asset-server-plugin
   /**
    * @param {string} packageNameInput
    * @returns {NpmPackage|null}
    */
   static fromString(packageNameInput) {
      if (!packageNameInput) {
         return null;
      }
      const regex = /^(?:@([^\/]+)\/)?([^@]+)(?:@(.+))?$/;
      const match = packageNameInput.match(regex);
      if (!match) {
         throw new Error(`Invalid packageName: ${packageNameInput}`);
      }
      const [, scope, name, version] = match;
      if (!name || !version) {
         throw new Error(`Invalid packageName: ${packageNameInput}`);
      }
      return new NpmPackage(packageNameInput, name, version, scope);
   }
}

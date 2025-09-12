export default class PotentialSink {

   /**
    * @param {LocationRange} location - Location as reported by codeQL. In case of a call expression, this is the location of argument to the callable.
    * @param {LocationRange|undefined} locationCallNode - Location of the call expression, if any.
    * @param {string} message
    */
   constructor(location, locationCallNode, message) {
      this.location = location;
      this.locationCallNode = locationCallNode;
      this.message = message;
   }
}

/**
 * Class representing a request to set a breakpoint.
 */
export default class BreakpointRequest {

   /**
    * Create a BreakpointRequest.
    * @param {Location} location - The location where the breakpoint is set.
    * @param {string} expression - The expression to evaluate at the breakpoint.
    */
   constructor(location, expression) {
      this.location = location;
      this.expression = expression;
   }

}

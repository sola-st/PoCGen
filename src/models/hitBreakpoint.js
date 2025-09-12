/**
 * @typedef {import('../models/BreakpointRequest').default} BreakpointRequest
 */

/**
 * @typedef {import('@types/node/inspector').Runtime.RemoteObject} RemoteObject
 */

/**
 * @typedef {Object} ResponseType
 * @property {string} [description]
 * @property {string} [value]
 * @property {string} [type]
 */

export default class HitBreakpoint {
   /**
    * @param {BreakpointRequest} breakpointRequest
    * @param {RemoteObject} runtimeObject
    */
   constructor(breakpointRequest, runtimeObject) {
      this.breakpointRequest = breakpointRequest;
      this.runtimeObject = runtimeObject;
   }
}

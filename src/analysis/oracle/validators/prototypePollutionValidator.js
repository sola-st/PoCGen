import { Validator } from "./validator.js";
import { wrapBackticks } from "../../../utils/utils.js";

export const ppName = "exploited";

const _defineProperty = Object.defineProperty;
const _defineProperties = Object.defineProperties;

const _getPrototypeOf = Object.getPrototypeOf;

export default class PrototypePollutionValidator extends Validator {

   /** @inheritDoc */
   async setup(config) {
      await super.setup(config);
      const self = this;

      const definePropertyHandler = function (target, propName, attributes) {
         if (propName === ppName && target === Object.prototype) {
            self.runtimeInfo.confirmed = true;
            if (self.isCallFromSource()) {
               self.log(`Confirmed`);
               self.runtimeInfo.confirmedFromSource = true;
            } else {
               self.log(`!fromSource Prototype pollution`);
            }
         }
         return _defineProperty(target, propName, attributes);
      }
      Reflect.set = function (target, propName, newValue, receiver) {
         if (propName !== ppName) {
            return Reflect.set(target, propName, newValue, receiver);
         }
         if (receiver !== Object.prototype) {
            return Reflect.set(target, propName, newValue, receiver);
         }
         self.runtimeInfo.confirmed = true;
         if (self.isCallFromSource()) {
            self.log(`Confirmed`);
            self.runtimeInfo.confirmedFromSource = true;
         } else {
            self.log(`!fromSource Prototype pollution`);
         }
         return Reflect.set(target, propName, newValue, receiver);
      };

      Object.defineProperties = function (target, properties) {
         if (target === Object.prototype && ppName in properties) {
            self.log("defineProperties");
            self.runtimeInfo.confirmed = true;
            if (self.isCallFromSource()) {
               self.log(`Confirmed`);
               self.runtimeInfo.confirmedFromSource = true;
            } else {
               self.log(`!fromSource Prototype pollution`);
            }
         }
         return _defineProperties(target, properties);
      }

      Object.defineProperty = definePropertyHandler;
      Reflect.defineProperty = definePropertyHandler;

      Object.prototype.__defineSetter__(ppName, function (val) {
         if (this !== Object.prototype) {
            return;
         }
         self.runtimeInfo.confirmed = true;
         if (self.isCallFromSource()) {
            self.log(`Confirmed defineSetter`);
            self.runtimeInfo.confirmedFromSource = true;
            Object.prototype._exploited = val;
         } else {
            self.log(`!fromSource Prototype pollution`);
         }
      });

      Object.prototype.__defineGetter__(ppName, function () {
         return Object.prototype._exploited;
      });
   }

   hookGlobal() {
      // https://github.com/v8/v8/blob/main/src/init/bootstrapper.cc#L928
      Object.prototype.__proto__ = new Proxy(Object.create(null), {
         getPrototypeOf(target) {
            return Reflect.getPrototypeOf(target);
         },
         defineProperty(target, property, attributes) {
            return definePropertyHandler(target, property, attributes);
         },
         set(target, propName, newValue, receiver) {
            return setHandler(target, propName, newValue, receiver);
         },
         get: function (target, propName) {
            return Reflect.get(target, propName);
         },
      });

      const getPrototypeOfHandler = function (target) {
         if (target === Object.prototype) {
            return null;
         }
         return _getPrototypeOf(target);
      }
      // objtools
      Object.getPrototypeOf = getPrototypeOfHandler;
      Reflect.getPrototypeOf = getPrototypeOfHandler;
   }
}

export const name = "Prototype Pollution";
export const label = "prototype-pollution";
export const cwe = [1321];
export const goal = `pollute the object prototype with a property ${wrapBackticks(ppName)}`;
export const validator = PrototypePollutionValidator;

export async function validate(exploit) {
   try {
      delete Object.prototype.exploited;
      await exploit();
   } catch (e) {
      console.error(e);
   }
   return "exploited" in Object.prototype;
}

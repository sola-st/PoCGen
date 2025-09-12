import {createRequire} from "node:module";
import LocationRange from "../models/locationRange.js";
import {rmPrefix} from "./utils.js";
import Location from "../models/location.js";

export const require = createRequire(import.meta.url);
const {getFunctionLocation} = require("function_location");

/**
 * @returns {Location} - The location of the function.
 */
Function.prototype.getLocation = function () {
   return getFunctionLocation(this);
};

/**
 * @param {Function} fn - The function to extract the source from.
 * @returns {Source} - The source object containing the function code and location.
 */
export function sourceFromFn(fn) {
   const location = fn.getLocation();
   return {
      callable: {
         code: fn.toString(),
         name: fn.name,
         location: LocationRange.fromLocation(
            new Location(
               rmPrefix(rmPrefix(location.filePath, "file://"), "/"),
               location.startLine,
               location.startColumn,
            ),
            fn.toString(),
         ),
      },
   };
}

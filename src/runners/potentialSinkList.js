import LocationRange from "../models/locationRange.js";

export default class PotentialSinkList {

   /**
    * @type {Array<{location: LocationRange, taintPaths: TaintPath[], potentialSinks: PotentialSink[]}>}
    */
   entries = [];

   /**
    *
    * @param {LocationRange} location
    * @param {PotentialSink} potentialSink
    * @param {TaintPath} taintPath
    */
   add(location, potentialSink, taintPath) {
      // Check if the location is already in the list
      for (let i = 0; i < this.entries.length; i++) {
         if (LocationRange.equals(this.entries[i].location, location)) {
            this.entries[i].potentialSinks.push(potentialSink);
            this.entries[i].taintPaths.push(taintPath);
            return;
         }
      }
      this.entries.push({
         location: location,
         potentialSinks: [potentialSink],
         taintPaths: [taintPath]
      });
   }
}

/**
 * @typedef {object} TaskEntry
 * @property {number} startTime - The time the task started
 * @property {number} duration - The duration of the task
 */

/**
 * Map to store task names as keys and their durations as values
 * @extends {Map<string, TaskEntry[]>}
 */
export default class PerformanceTracker extends Map {

   /**
    * Marks a task, runs a function, and stops the task after the function completes.
    * @template T
    * @param {string} taskName - The name of the task to mark.
    * @param {() => Promise<T>} fn - An asynchronous function to execute.
    * @returns {Promise<T>} - The result of the executed function.
    */
   async markFn(taskName, fn) {
      const startTime = Date.now();
      let result;
      try {
         result = await fn();
      } finally {
         const end = Date.now();
         if (!this.has(taskName)) {
            this.set(taskName, []);
         }
         this.get(taskName).push({startTime, duration: end - startTime});
      }
      return result;
   }

   markFnSync(taskName, fn) {
      const startTime = Date.now();
      let result;
      try {
         result = fn();
      } finally {
         const end = Date.now();
         if (!this.has(taskName)) {
            this.set(taskName, []);
         }
         this.get(taskName).push({startTime, duration: end - startTime});
      }
      return result;
   }

   toJSON() {
      return Object.fromEntries(this);
   }
}

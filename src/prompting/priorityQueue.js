export default class PriorityQueue {
   /**
    * @type {{priority: number, refiner: DefaultRefiner}[]}
    */
   queue = [];

   /**
    * @param {DefaultRefiner} refiner
    * @param {number} priority
    */
   enqueue(refiner, priority) {
      this.queue.push({priority, refiner});
   }

   /**
    * @returns {{priority: number, refiner: DefaultRefiner}}
    */
   dequeue() {
      if (this.isEmpty()) {
         throw new Error("Queue is empty");
      }
      let biggest;
      for (const element of this.queue) {
         if (!biggest || element.priority > biggest.priority) {
            biggest = element;
         }
      }
      this.queue = this.queue.filter((element) => element !== biggest);
      return biggest;
   }

   isEmpty() {
      return this.queue.length === 0;
   }

   get length() {
      return this.queue.length;
   }
}

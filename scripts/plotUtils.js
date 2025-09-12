export function getMedian(arr) {
   const len = arr.length;
   const mid = Math.floor(len / 2);

   if (len % 2 === 0) {
      return (arr[mid - 1] + arr[mid]) / 2;
   } else {
      return arr[mid];
   }
}

export function getBoxplotData(data) {
   const sorted = [...data].sort((a, b) => a - b);

   const median = getMedian(sorted);

   const lowerHalf = sorted.slice(0, Math.floor(sorted.length / 2));
   const upperHalf = sorted.slice(Math.ceil(sorted.length / 2));

   const q1 = getMedian(lowerHalf);
   const q3 = getMedian(upperHalf);
   const iqr = q3 - q1;

   const lowerFence = q1 - 1.5 * iqr;
   const upperFence = q3 + 1.5 * iqr;

   const min = Math.min(...sorted.filter(n => n >= lowerFence));
   const max = Math.max(...sorted.filter(n => n <= upperFence));

   return {
      min,
      q1,
      median,
      q3,
      max,
      iqr,
      outliers: sorted.filter(n => n < lowerFence || n > upperFence)
   };
}

export default class StoppedFunction {

   /**
    * @param {FunctionSnippet} functionSnippet
    * @param {number} stoppedFunctionIdx
    * @param {boolean} entireFunctionNotExecuted
    */
   constructor(functionSnippet, stoppedFunctionIdx, entireFunctionNotExecuted) {
      this.functionSnippet = functionSnippet;
      this.stoppedFunctionIdx = stoppedFunctionIdx;
      this.entireFunctionNotExecuted = entireFunctionNotExecuted;
      this.sourceFunctionExecuted = !(this.stoppedFunctionIdx === 0 && this.entireFunctionNotExecuted);
   }
}

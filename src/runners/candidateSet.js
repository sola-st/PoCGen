/**
 * @type {{FALLBACK_LEVEL_DYNAMIC: number, FALLBACK_LEVEL_LLM_SINK: number, FALLBACK_LEVEL_CODEQL_LESS_STRICT: number, FALLBACK_LEVEL_CODEQL: number}}
 */
export const TaintPathType = {
   DEFAULT: 0,
   FALLBACK_TAINT_PROPAGATOR: 1,
   FALLBACK_LLM_SINK: 2,
   FALLBACK_LEVEL_DYNAMIC: 3,
}

export class SourceCandidate {

   /**
    * @type {number}
    */
   fallbackLevel = TaintPathType.DEFAULT;

   /**
    * @type {Source}
    */
   source;

   /**
    * @type {TaintPath[]}
    */
   taintPaths;

   /**
    * If we found a taint path for the source with lower priority level we exclude it from analysis
    * @type {boolean}
    */
   freeze = false;

   constructor(source, taintPaths) {
      this.source = source;
      this.taintPaths = taintPaths;
   }

   hasTaintPath() {
      return this.taintPaths.length > 0;
   }

   hasPotential() {
      if (this.hasTaintPath())
         return true;
      return !this.freeze && this.fallbackLevel <= TaintPathType.FALLBACK_LEVEL_DYNAMIC;
   }

}

export class CandidateSet {

   /**
    * @param {SourceCandidate[]} sources
    */
   candidates;

   /**
    * @param {Source[]} sources
    */
   constructor(sources) {
      this.candidates = sources.map((source) =>
         new SourceCandidate(source, [])
      );
   }

   hasPotential() {
      return this.candidates.some((candidate) => candidate.hasPotential());
   }
}

export class CandidateSets {
   /**
    * @param {CandidateSet[]} candidatSets
    */
   #candidateSets = [];

   /**
    * @returns {CandidateSet}
    */
   next() {
      // get first candidate set with lowest fallback level
      const sorted = this.#candidateSets.toSorted((a, b) => a.fallbackLevel - b.fallbackLevel);
      return sorted[0];
   }

   push(candidateSet) {
      this.#candidateSets.push(candidateSet);
   }

   hasPotential() {
      return this.#candidateSets.some((candidateSet) => candidateSet.hasPotential());
   }
}

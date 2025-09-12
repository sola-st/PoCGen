import {join} from "node:path";
import DefaultRefiner from "../src/prompting/refiners/default.refiner.js";

export const CWE_BENCH = "CWEBench.js"
export const SEC_BENCH = "SecBench.js"
export const DATASET_NAMES = [CWE_BENCH, SEC_BENCH]

export const VULNERABILITY_LABELS_MAP = {
   "redos": "ReDoS",
   "path-traversal": "Path Traversal",
   "prototype-pollution": "Prototype Pollution",
   "code-injection": "Code Injection",
   "command-injection": "Command Injection",
}

export const DEFAULT = "default";

export function isDefaultRefinerName(n) {
   return [DEFAULT, DefaultRefiner.name].includes(n)
}

export const VULNERABILITY_LABELS = Object.keys(VULNERABILITY_LABELS_MAP)

export const LABELS = {
   TP: "y",
   FP: "fp",
   TN: ""
}

/**
 * Directory that contains the labeled dataset.
 * Required folder structure:
 * ```
 * <dataset-name>
 *    - <refiner-name>
 *       - <UPPERCASE(vulnerability-type)>.md
 * ```
 *
 * The folder with the vulnerability type must be named in uppercase.
 * If <refiner-name> is equal to {@link DEFAULT}, the markdown files are loaded from <dataset-name>/.
 *
 * @type {string}
 */
export const LABELS_DIR = "/home/user/Uni/thesis/paper/vault/pipeline/"

/**
 * Directory that contains the results of the analysis.
 * Required folder structure:
 * ```
 * <dataset-name>
 *    - <advisory-id>
 *       - RunnerResult_<refiner-name>.json
 * ```
 * @type {string}
 */
export const RESULTS_DIR = join(import.meta.dirname, "..", "results");

/**
 * Directory that stores the transformed version of the labeled dataset.
 * @type {string}
 */
export const DATASET_DIR = join(import.meta.dirname, "..", "dataset");

/**
 * Directory that contains the compiled PDFs.
 * @type {string}
 */
export const FIGURES_REPO_DIR = join(import.meta.dirname, "..", "figures");

/**
 * Directory that contains the figures for the paper.
 * @type {string}
 */
export const FIGURES_DIR = "/home/user/Uni/thesis/paper/figures/"

export const CUT_OFF_DATE = new Date("2023-10-01");

export const refinerLabelsMapping = {
   "C8Refiner": "noTaintPath",
   "C7Refiner": "noAPIRefs",
   "C6Refiner": "noFewShot",
   "C3Refiner": "noDebugger",
   "C2Refiner": "noRuntimeFeedback",
}

# PoCGen: Generating Proof-of-Concept Exploits for Vulnerable npm Packages

This repository contains the tool to generate proof-of-concept exploits for vulnerable npm packages, in addition, it contains the datasets used for the evaluation.

## Setup

1. Clone the repository:

```sh
git clone https://github.com/sola-st/PoCGen
cd PoCGen
```

2. Install dependencies:

> You need Node.js and npm installed.

```sh
npm install
```

> You need `docker` installed for steps below.

3. Option 1: Use the pre-built docker image (recommended):

```sh
docker pull aryaze/pocgen:v1.0
docker tag aryaze/pocgen:v1.0 gen-poc_mnt
```

3. Option 2: Build the docker images (this may take a while):

```sh
docker build -t patched_node -f patched_node.Dockerfile .
docker build -t gen-poc_mnt .
```

## Environment Variables

The repository contains a wrapper script to run the tool in a docker container.
The script requires an `.env` file in the current directory with the following content:

```
OPENAI_API_KEY=sk-proj-xxx    # required for LLM calls
GITHUB_API_KEY=github_pat_xxx # required for fetching vulnerabilities from GitHub Security Advisories database
```

The only required argument is the vulnerability ID, which can be a GitHub Advisory ID or a Snyk ID.
The tool will automatically fetch the vulnerability report from the corresponding API/ scrape it from the website.

## Create a PoC for a vulnerable package

Run this script from the repository root:

```sh
./run-mnt.sh output node index.js create -v GHSA-m7p2-ghfh-pjvx
```

This will create a test for [GHSA-m7p2-ghfh-pjvx](https://github.com/advisories/GHSA-m7p2-ghfh-pjvx) in
`./output/GHSA-m7p2-ghfh-pjvx/test.js`.

## Running the test

For most vulnerabilities, it is recommended to run the test using the provided docker image:

```sh
./run-mnt.sh output node --test /output/<advisoryId>/test.js
```

For **ReDoS** vulnerabilities, the test should be run with the following flags:

```sh
./run-mnt.sh output node --test --enable-experimental-regexp-engine-on-excessive-backtracks --regexp-backtracks-before-fallback=30000 output/<advisoryId>/test.js
```

For vulnerabilities that involve long-running tasks (e.g. web servers), run the test with the following flags:

```sh
./run-mnt.sh output node --test --test-force-exit /output/<advisoryId>/test.js
```

## Repository Structure

The repository contains
- the source code of PoCGen in `src/`
    - `analysis`: static and dynamic analyses used in PoCGen
    - `model`: LLM models and utilities
    - `models`: Javascript classes
    - `npm`: utilities for dealing with npm packages
    - `pipeline`: the main pipeline for generating PoC exploits
    - `prompting`: prompt templates, and prompt generation utilities
    - `resources`: CodeQL query templates, and the command injection code
    - `runners`: various runners (e.g., the agent) used to generate PoC exploits
    - `utils`: general utility functions
    - `vulnerability-databases`: scripts to retrieve vulnerability data from various sources
- the datasets used for the evaluation in `dataset/`
- the scripts to summarize, aggregate, and visualize the results in `scripts/`
- some helper functions in `lib/`

## Reproducing the Evaluation Results

We provide 3 levels for reproducing results based on the time and monetary costs:
1. Inspecting and visualizing the results based on logs from our runs (no LLM costs involved, and very low execution time).
2. Running PoCGen on a single vulnerability (low LLM costs, and low execution time).
3. Running PoCGen on the full dataset (high LLM costs, and high execution time).

To follow on level 1, download the evaluation results from [Zenodo](https://doi.org/10.5281/zenodo.19482271), and then follow the instructions labeled with "level 1" below.

To evaluate on level 2, follow the instructions in the previous sections.

To evaluate on level 3, follow the instructions in the "Setup" section, and then follow the instructions labeled with "level 3" below.

### RQ1: Effectiveness

(level 3) To run PoCGen on the SecBench.js dataset, use the following command:

```sh
./run-mnt.sh output node index.js pipeline -v dataset/SecBench.js/*\.all
```

This creates a directory under `output` with the IDs of each vulnerability as a subdirectory.
Each subdirectory contains the vulnerable package, an execution log file named `output_*.log` (showing the steps and execution outputs), an LLM interaction log file named `prompt.json` (showing the LLM interactions with all the metadata), a json file contaning all the information about the attempt named `RunnerResult_*.json`, and the proof-of-concept exploit as a test file named `test.js`.

(level 3) To run Mini-SWE-agent on the SecBench.js dataset, use the following command:

```sh
./run-mnt.sh output node index.js pipeline --runner RunnerMiniSWEAgent -v dataset/SecBench.js/*\.all
```

This creates the same directory structure, with the difference that it creates a `mini_swe_workspace` subdirectory for each vulnerability and stores the PoC exploit in it as `poc.js`.

(level 1) The generated PoC exploits can be found in `eval_results/pocgen_*/<vulnerability_id>/test.js` and `eval_results/minisweagent_*/<vulnerability_id>/mini_swe_workspace/poc.js`.


### RQ2: Ablation Study

(level 3) A refiner can be specified using `--refiner <refiner>`. I.e.,
```sh
./run-mnt.sh output node index.js pipeline -v dataset/SecBench.js/*\.all --refiner C0Refiner
```
The following values were used in the evaluation:
- `noTaint` for noTaint
- `C7Refiner` for noUsageSnippets
- `C6Refiner` for noFewShot
- `C3Refiner` for noDebugger
- `C2Refiner` for noErrorRefiner

(level 1) The generated PoC exploits of the ablation study can be found in `eval_results/pocgen_<refiner name>/<vulnerability_id>/test.js`.


### RQ3: Costs

(level 1 & 3)

For each vulnerability the token costs are stored in the `RunnerResult_*.json` file under the `model.totalPromptTokens` and `model.totalCompletionTokens` fields for request and response tokens respectively.

To get the average token costs for PoCGen, you can run

```sh
python scripts/count_tokens.py <output_directory>
```
`<output_directory>` can be any of the subdirectories in `eval_results` of the format `pocgen_*`.

To get the average costs for Mini-SWE-agent, you can run

```sh
python scripts/count_agent_tokens.py <output_directory>
```
`<output_directory>` can be any of the subdirectories in `eval_results` of the format `minisweagent_*`.


### RQ4: Newer Vulnerabilities

(level 3) To run PoCGen on vulnerabilities reported in 2025-2026, use the following command:

```sh
./run-mnt.sh output node index.js pipeline -v dataset/ghsa_2025-2026.txt
```

(level 1) The generated PoC exploits can be found in `eval_results/pocgen_2025-2026/<vulnerability_id>/test.js`.


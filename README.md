# PoCGen: Generating Proof-of-Concept Exploits for Vulnerable npm Packages

This repository contains the tool to generate proof-of-concept exploits for vulnerable npm packages, in addition, it contains the evaluation results, LLM prompts and responses, and the datasets used for the evaluation.

## Building the Docker Image

1. Clone the repository:

```sh
git clone https://github.com/sola-st/PoCGen
```

2. Install dependencies:

```sh
cd PoCGen
npm install
```

3. Build the docker images:

> You need `docker` installed.

```sh
docker build -t patched_node -f patched_node.Dockerfile .
docker build -t gen-poc_mnt .
```

## Setup

The repository contains a wrapper script to run the tool in a docker container.
The script requires an `.env` file in the current directory with the following content:

```
OPENAI_API_KEY=sk-proj-xxx    # required for LLM calls
GITHUB_API_KEY=github_pat_xxx # required for fetching GHSA-IDs
```

The only required argument is the vulnerability ID, which should be a GitHub Advisory ID or a Snyk ID.
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

## Reproducing the Evaluation Results

> Note that running the following commands will run PoCGen or the baseline on large datasets (more than 100 vulnerabilities), which takes multiple hours and incurs costs for API calls to an LLM.
> We have included the interactions with the LLM and all the logs and metadata of the runs in the `eval_results` directory.

First, follow the installation instructions above.

### RQ1: Effectiveness

To run PoCGen on the SecBench.js dataset, use the following command:

```sh
./run-mnt.sh output node index.js pipeline -v dataset/SecBench.js/*\.all
```

This creates a directory under `output` with the IDs of each vulnerability as a subdirectory.
Each subdirectory contains the vulnerable package, an execution log file named `output_*.log` (showing the steps and execution outputs), an LLM interaction log file named `prompt.json` (showing the LLM interactions with all the metadata), a json file contaning all the information about the attempt named `RunnerResult_*.json`, and the proof-of-concept exploit as a test file named `test.js`.

To run Mini-SWE-agent on the SecBench.js dataset, use the following command:

```sh
./run-mnt.sh output node index.js pipeline --runner RunnerMiniSWEAgent -v dataset/SecBench.js/*\.all
```

This creates the same directory structure, with the difference that it creates a `mini_swe_workspace` subdirectory for each vulnerability and stores the PoC exploit in it as `poc.js`.


### RQ2: Ablation Study

A refiner can be specified using `--refiner <refiner>`. I.e.,
```sh
./run-mnt.sh output node index.js pipeline -v dataset/SecBench.js/*\.all --refiner C0Refiner
```
The following values were used in the evaluation:
- `noTaint` for noTaint
- `C7Refiner` for noUsageSnippets
- `C6Refiner` for noFewShot
- `C3Refiner` for noDebugger
- `C2Refiner` for noErrorRefiner



### RQ3: Costs

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

To run PoCGen on vulnerabilities reported in 2025-2026, use the following command:

```sh
./run-mnt.sh output node index.js pipeline -v dataset/ghsa_2025-2026.txt
```


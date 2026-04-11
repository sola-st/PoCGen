import { Runner } from "./runner.js";
import { renderPromptTemplate } from "../prompting/promptGenerator.js";
import { loadModels } from "../model/model.js";
import { join, dirname } from "node:path";
import { recCopy } from "../utils/utils.js";
import { mkdirSync, writeFileSync, copyFileSync } from "fs";
import { spawn } from "child_process";
import RunnerResult from "./runnerResult.js";
import { execSync, spawnSync } from "node:child_process";
import { fileURLToPath } from 'url';
import { readFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));

const indent = (str, spaces = 4) => {
    if (!str) return str;
    return str.split('\n').join('\n' + ' '.repeat(spaces));
};

process.on(
    "message",
    async (options) => {
        const runner = new RunnerMiniSWEAgent(options);
        await runner.start();
        process.send(RunnerResult.prototype.toJSON.apply(runner));
    },
);

const runSetup = () => {
    return new Promise((resolve, reject) => {
        const child = spawn('mini-extra', ['config', 'setup']);
        child.stdout.on('data', (data) => {
            if (data.includes("Enter your default model")) {
                child.stdin.write("openai/gpt-5-mini\n");
            } else if (data.includes("Enter your API key name")) {
                child.stdin.write("OPENAI_API_KEY\n");
            } else if (data.includes("Enter your API key value")) {
                child.stdin.write(process.env.OPENAI_API_KEY + "\n");
            }
        });
        child.stderr.on('data', (data) => {
            process.stderr.write(data);
        });
        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Setup failed with exit code ${code}`));
            }
        });
    });
}

export default class RunnerMiniSWEAgent extends Runner {

    async run() {
        await this.setupWorkingDir();
        this.setupLogging();

        const lmModule = (await loadModels()).find((m) => m.name === this.opts.model);
        this.model = new lmModule.default(this.opts);

        this.vulnerabilityDescription = indent(await this.getRedactedDescription());

        const yamlFilepath = join(this.baseDir, "mini_swe_config.yaml");
        let task = readFileSync(join(__dirname, "minisweagent.yaml"), "utf8");
        task = task.replace("{{task}}", this.vulnerabilityDescription);
        writeFileSync(yamlFilepath, task, "utf8");

        // 1. Prepare Local Workspace
        // We create a dedicated directory for this specific agent run
        const workspaceBaseDir = join(this.baseDir, "mini_swe_workspace");
        mkdirSync(workspaceBaseDir, { recursive: true });

        const projectDir = join(workspaceBaseDir, "project");
        mkdirSync(projectDir, { recursive: true });

        // Copy the target code (node_modules and source) into the project dir
        recCopy(this.nmPath, join(projectDir, "node_modules"));
        // If you have other source files to copy, do it here:
        // recCopy(this.sourcePath, projectDir);

        // 2. Prepare the Issue/Goal
        const goal = renderPromptTemplate("exploitCreation/goalAgent", {
            package: this.package,
            vulnerabilityDescription: this.vulnerabilityDescription,
            workspace: projectDir,
        });

        const issueFilePath = join(workspaceBaseDir, "issue.txt");
        writeFileSync(issueFilePath, goal, 'utf8');


        // execSync("pip install --pre mini-swe-agent", { stdio: "inherit" });
        // 3. Execution Arguments
        // Using the CLI flags typically supported by mini-swe-agent
        const args = [
            '--config', yamlFilepath,
            '--task', '"Generate a proof-of-concept exploit for the vulnerability"',
            '-y'
        ];

        await runSetup();


        execSync("mini-extra config set MSWEA_MODEL_NAME openai/gpt-5-mini", { stdio: "inherit" });
        execSync("mini-extra config set OPENAI_API_KEY " + process.env.OPENAI_API_KEY, { stdio: "inherit" });
        execSync("mini-extra config set MSWEA_SILENT_STARTUP true", { stdio: "inherit" });
        execSync("mini-extra config set MSWEA_MINI_CONFIG_PATH " + yamlFilepath, { stdio: "inherit" });
        execSync("mini-extra config set MSWEA_GLOBAL_CALL_LIMIT 30", { stdio: "inherit" });

        console.info(`Starting mini-swe-agent via CLI: mini ${args.join(" ")}`);

        const self = this;
        return new Promise((resolve, reject) => {
            // Spawn the CLI directly instead of Docker
            const child = spawn('mini', args, {
                cwd: workspaceBaseDir,
                env: {
                    ...process.env,
                    // Ensure the agent has the API key in its environment
                    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
                    MSWEA_MODEL_NAME: 'openai/gpt-5-mini',
                    MSWEA_MINI_CONFIG_PATH: yamlFilepath,
                    MSWEA_SILENT_STARTUP: 'true',
                },
                stdio: 'pipe'
            });

            child.stdout.setEncoding('utf8');
            child.stderr.setEncoding('utf8');

            child.stdout.on('data', (data) => {
                const output = data.toString();
                process.stdout.write(output);
                if (output.includes("What do you want to do")) {
                    child.stdin.write(goal + "\n");
                } else if (output.includes("Agent wants to finish")) {
                    child.stdin.write("\n");
                }

                // Optional: Token tracking via regex if the CLI supports it
                // const matches = output.match(/tokens:.*?(\d+).*?input.*?(\d+).*?output/i);
                // if (matches) {
                //     self.model.uncachedPromptsUsage.promptTokens += parseInt(matches[1]);
                //     self.model.uncachedPromptsUsage.completionTokens += parseInt(matches[2]);
                // }
            });

            child.stderr.on('data', (data) => {
                console.error(`[mini-swe-agent error]: ${data}`);
            });

            child.on('close', (code) => {
                console.log(`Agent process exited with code ${code}`);
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`Agent failed with exit code ${code}`));
                }
            });

            // Error handling for when the command doesn't exist in path
            child.on('error', (err) => {
                console.error("Failed to start mini-swe-agent. Ensure it is installed via pip and in your PATH.");
                reject(err);
            });
        });
    }
}
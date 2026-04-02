import { Runner } from "./runner.js";
import { renderPromptTemplate } from "../prompting/promptGenerator.js";
import { loadModels } from "../model/model.js";
import { join } from "node:path";
import { recCopy } from "../utils/utils.js";
import { mkdirSync, writeFileSync } from "fs";
import { spawn } from "child_process";
import { basename } from "path";
import RunnerResult from "./runnerResult.js";

process.on(
   "message",
   async (options) => {
      const runner = new RunnerAgent(options);
      await runner.start();
      process.send(RunnerResult.prototype.toJSON.apply(runner));
   },
);

export default class RunnerAgent extends Runner {

   async run() {
      await this.setupWorkingDir();
      this.setupLogging();

      const lmModule = (await loadModels()).find((m) => m.name === this.opts.model);
      this.model = new lmModule.default(this.opts);

      this.vulnerabilityDescription = await this.getRedactedDescription();

      const agentName = this.advisory.id.replaceAll("/", "_");

      const autogptDirContainer = "/app/autogpt/data"

      const workspaceContainer = join(autogptDirContainer, "agents", agentName, "workspace");

      const goal = renderPromptTemplate("exploitCreation/goalAgent", {
         package: this.package,
         vulnerabilityDescription: this.vulnerabilityDescription,
         workspace: workspaceContainer,
      })

      let sysPrompt = "a seasoned digital assistant: capable, intelligent, considerate and assertive. You have extensive research and development skills, and you don't shy away from writing some code to solve a problem. You are pragmatic and make the most out of the tools available to you.";

      const state = {
         "name": "Agent",
         "description": "",
         "agent_id": agentName,
         "ai_profile": {
            "ai_name": agentName,
            "ai_role": sysPrompt,
            "ai_goals": []
         },
         "directives": {
            "resources": [],
            "constraints": [],
            "best_practices": []
         },
         "task": goal,
         "config": {
            "allow_fs_access": true,
            /*   "fast_llm": "gpt-3.5-turbo",
               "smart_llm": "gpt-4-turbo",*/
            "fast_llm": "gpt-5-mini",
            "smart_llm": "gpt-5-mini",
            "use_functions_api": false,
            "default_cycle_instruction": "Determine exactly one command to use next based on the given goals and the progress you have made so far, and respond using the JSON schema specified previously:",
            "big_brain": true,
            "cycle_budget": 1,
            "cycles_remaining": 1,
            "cycle_count": 3,
            "send_token_limit": null
         },
         "history": {
            "episodes": [],
            "cursor": 0
         },
         "context": {
            "items": []
         }
      }

      const workspaceBaseDir = join(this.baseDir, "agent_workspace");
      mkdirSync(workspaceBaseDir, { recursive: true });

      // Add .env
      const envFilePath = join(workspaceBaseDir, ".env");
      const envContent = `
         OPENAI_API_KEY=${process.env.OPENAI_API_KEY}
         TELEMETRY_OPT_IN=False,
         RESTRICT_TO_WORKSPACE=True
         SMART_LLM_MODEL=gpt-5-mini
         FAST_LLM_MODEL=gpt-5-mini
         FAST_TOKEN_LIMIT=4000
         SMART_TOKEN_LIMIT=8000
         EXECUTE_LOCAL_COMMANDS=True
         DISABLED_COMMANDS=ask_user,execute_python_code,execute_python_file,web_search,search,read_webpage
      `.trim().split("\n").map(line => line.trim()).join("\n");
      writeFileSync(envFilePath, envContent, 'utf8');

      // Add state.json
      const agentBaseDir = join(workspaceBaseDir, "agents", agentName);
      mkdirSync(agentBaseDir, { recursive: true });
      const stateFilePath = join(agentBaseDir, "state.json");
      const stateContent = JSON.stringify(state, null, 2);
      writeFileSync(stateFilePath, stateContent, 'utf8');

      // Add project source code
      const workspaceDir = join(agentBaseDir, "workspace");
      mkdirSync(workspaceDir, { recursive: true });
      const baseName = basename(this.nmModulePath);
      // recCopy(this.nmModulePath, join(workspaceDir, baseName));

      // Copy node_modules
      recCopy(this.nmPath, join(workspaceDir, "node_modules"));

      if (!process.env.HOST_BASE_DIR) {
         throw new Error("HOST_BASE_DIR environment variable is not set. Please set it to the host base directory for the agent workspace.");
      }
      const hostBaseDir = join(
         process.env.HOST_BASE_DIR,
         this.advisory.id.replace(/[^a-zA-Z0-9\-]/g, "_"),
         "agent_workspace"
      );
      console.info(`Host base directory: ${hostBaseDir}`);

      const args = [
         'run',
         '--rm',
         '-i',
         '--env-file', envFilePath,
         '-v', `${hostBaseDir}/:${autogptDirContainer}`,
         'autogpt_agent',
         'run',
         '--skip-news',
         "-c",
         "--ai-name", agentName,
         "--debug"
      ]

      console.info(`Starting agent ${agentName} with command: docker ${args.join(" ")}`);

      const self = this;
      return new Promise(async function (resolve, reject) {

         const child = spawn('docker', args,
            {
               cwd: workspaceBaseDir,
               stdio: ['pipe', 'pipe', 'pipe']
            });

         child.stdout.setEncoding('utf8');
         child.stderr.setEncoding('utf8');

         child.stdout.on('data', (data) => {
            const output = data.toString();
            process.stdout.write(output);

            const matches = output.match(/completion usage: (\d+) input, (\d+) output/);
            if (matches) {
               console.warn(`Completion usage: ${matches[1]} input, ${matches[2]} output`);
               const inputTokens = parseInt(matches[1]);
               const outputTokens = parseInt(matches[2]);
               self.model.uncachedPromptsUsage.promptTokens += inputTokens;
               self.model.uncachedPromptsUsage.completionTokens += outputTokens;
            }

            if (output.includes("Enter the task that you want AutoGPT to execute, with as much detail as possible:")) {
               child.stdin.write(goal.replaceAll("\n", "\\n"));
               child.stdin.write('\n');
            }
            if (output.includes("Enter the number or name of the agent to run, or hit enter to create a new one:")) {
               child.stdin.write('1\n');
            }
            if (output.includes("Continue with these settings? [Y/n] ")) {
               child.stdin.write('Y');
               child.stdin.write('\n');
            }
            if (output.includes("Enter the number or name of the agent to run, or hit enter to create a new one: ")) {
               child.stdin.write('\n');
            }
            if (output.includes("Press enter to save as '")) {
               child.stdin.write('\n');
               self.finished = true;
            }
         });

         child.stderr.on('data', (data) => {
            console.error(`Child Error: ${data}`);
         });

         child.on('close', (code) => {
            console.log(`Child process exited with code ${code}`);
            if (self.finished) {
               resolve();
            } else {
               reject(new Error(`Child process exited with code ${code}`));
            }
         });

      });
   }
}

#!/usr/bin/env node

import {readFileSync, readdirSync, writeFileSync} from "node:fs";
import {join, resolve} from "node:path";

/**
 * Recursively find all prompt.json files in a directory
 * @param {string} dir
 * @returns {string[]}
 */
function findPromptJsonFiles(dir) {
   const files = [];
   try {
      const entries = readdirSync(dir, {withFileTypes: true});
      for (const entry of entries) {
         const fullPath = join(dir, entry.name);
         if (entry.isDirectory()) {
            files.push(...findPromptJsonFiles(fullPath));
         } else if (entry.name === "prompt.json") {
            files.push(fullPath);
         }
      }
   } catch (e) {
      // Skip directories we can't read
   }
   return files;
}

/**
 * Count occurrences of a substring in a string
 * @param {string} str
 * @param {string} substr
 * @returns {number}
 */
function countOccurrences(str, substr) {
   if (!str) return 0;
   return (str.match(new RegExp(substr.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length;
}

/**
 * Analyze a single prompt.json file
 * @param {string} filePath
 * @returns {Object[]}
 */
function analyzePromptFile(filePath) {
   const issues = [];

   try {
      const content = readFileSync(filePath, "utf-8");
      const prompts = JSON.parse(content);

      if (!Array.isArray(prompts)) {
         return issues;
      }

      for (let i = 0; i < prompts.length - 1; i++) {
         const current = prompts[i];
         const next = prompts[i + 1];

         if (!current.response || !Array.isArray(current.response.functionCalls)) {
            continue;
         }

         // Count debugExpressions function calls in current response
         const debugExpressionCalls = current.response.functionCalls.filter(
            (call) => call.name === "debugExpressions"
         );

         if (debugExpressionCalls.length > 1) {
            const k = debugExpressionCalls.length;

            // Count "// value of" substrings in next prompt's userPrompt
            const nextUserPrompt = next.prompt?.userPrompt || "";
            const valueOfCount = countOccurrences(nextUserPrompt, "// value of");

            if (valueOfCount < k) {
               issues.push({
                  filePath,
                  promptIndex: i,
                  debugExpressionCount: k,
                  valueOfCount: valueOfCount,
                  currentPrompt: current.prompt?.userPrompt || "(N/A)",
                  nextPrompt: next.prompt?.userPrompt || "(N/A)",
               });
            }
         }
      }
   } catch (e) {
      console.error(`Error reading ${filePath}: ${e.message}`);
   }

   return issues;
}

// Main execution
const outputDir = resolve(process.argv[2] || "./output");
const reportFile = resolve(process.argv[3] || "./debug_expression_inconsistencies.txt");

console.log(`Scanning for prompt.json files in: ${outputDir}\n`);

const promptFiles = findPromptJsonFiles(outputDir);
console.log(`Found ${promptFiles.length} prompt.json file(s)\n`);

let totalIssues = 0;
let reportContent = `Debug Expression Inconsistencies Report\n`;
reportContent += `Generated: ${new Date().toISOString()}\n`;
reportContent += `Output directory: ${outputDir}\n`;
reportContent += `=`.repeat(80) + `\n\n`;

for (const file of promptFiles) {
   const issues = analyzePromptFile(file);
   totalIssues += issues.length;

   if (issues.length > 0) {
      const consoleMsg = `\n📄 ${file}`;
      const consoleCount = `   Found ${issues.length} inconsistenc${issues.length === 1 ? "y" : "ies"}:`;
      console.log(consoleMsg);
      console.log(consoleCount);

      reportContent += `\n📄 ${file}\n`;
      reportContent += `   Found ${issues.length} inconsistenc${issues.length === 1 ? "y" : "ies"}:\n`;

      for (const issue of issues) {
         const consoleDetail = `\n   Prompt #${issue.promptIndex}:\n   - Debug expressions in response: ${issue.debugExpressionCount}\n   - "// value of" in next prompt: ${issue.valueOfCount}\n   - Current prompt snippet: "${issue.currentPrompt.substring(0, 100)}..."\n   - Next prompt snippet: "${issue.nextPrompt.substring(0, 100)}..."`;
         console.log(consoleDetail);

         reportContent += `\n   Prompt #${issue.promptIndex}:\n`;
         reportContent += `   - Debug expressions in response: ${issue.debugExpressionCount}\n`;
         reportContent += `   - "// value of" in next prompt: ${issue.valueOfCount}\n`;
         reportContent += `   - Current prompt snippet: "${issue.currentPrompt.substring(0, 100)}..."\n`;
         reportContent += `   - Next prompt snippet: "${issue.nextPrompt.substring(0, 100)}..."\n`;
      }
   }
}

const summaryMsg = `\n\n📊 Summary: Found ${totalIssues} total inconsistenc${totalIssues === 1 ? "y" : "ies"} across all files`;
console.log(summaryMsg);

reportContent += `\n\n${"=".repeat(80)}\n`;
reportContent += `Summary: Found ${totalIssues} total inconsistenc${totalIssues === 1 ? "y" : "ies"} across all files\n`;

try {
   writeFileSync(reportFile, reportContent);
   console.log(`\n✅ Report written to: ${reportFile}`);
} catch (e) {
   console.error(`\n❌ Error writing report to ${reportFile}: ${e.message}`);
}

process.exit(totalIssues > 0 ? 1 : 0);

import {isNumber, kebabToCamel, loadEnv} from "../src/utils/utils.js";
import fs from "fs";
import {join} from "node:path";
import {isValidGhsaId} from "../src/vulnerability-databases/ghsaApi.js";
import {isValidSnykId} from "../src/vulnerability-databases/snykApi.js";
import {loadRunnerResultsVulnIds} from "./loadRunnerResults.js";
import DefaultRefiner from "../src/prompting/refiners/default.refiner.js";
import {getBoxplotData} from "./plotUtils.js";
import {
   CUT_OFF_DATE,
   CWE_BENCH,
   FIGURES_DIR,
   refinerLabelsMapping,
   RESULTS_DIR,
   SEC_BENCH,
   VULNERABILITY_LABELS,
   VULNERABILITY_LABELS_MAP
} from "./constants.js";
import {loadLabeledDataSet} from "./loadDataSetLabels.js";
import {fileURLToPath} from "node:url";
import {DataSet} from "./models/dataSet.js";
import {MAX_COMPLETION_TOKENS, MAX_PROMPT_TOKENS} from "../index.js";
import {loadRefiners} from "../src/prompting/promptRefiner.js";
import {loadExplodeJsDataSet} from "./explodeJsDataSet.js";

loadEnv();

const stats = {
   numSecbenchTotalUnfiltered: 600,
   dsname: CWE_BENCH,
};

/**
 * @param {DataSet} dataSet
 * @param {function(DataSetEntry): number} transformer
 * @returns {string}
 */
function boxPlot(dataSet, transformer) {
   const success = [];
   for (const entry of dataSet.working) {
      const r = transformer(entry);
      if (isNumber(r) && !isNaN(r)) {
         success.push(r);
      } else {
         console.log(`Invalid cost for ${entry.advisory.id}`);
      }
   }
   const failure = [];
   for (const entry of dataSet.failures) {
      const r = transformer(entry);
      if (isNumber(r) && !isNaN(r)) {
         failure.push(r);
      } else {
         console.log(`Invalid cost for ${entry.advisory.id}`);
      }
   }

   let code = "";
   for (const ds of [success, failure]) {
      console.log(`Processing ${ds.length} elements`);
      const sdata = getBoxplotData(ds);

      code += `\\addplot+[
                boxplot prepared={
                        median=${sdata.median},
                        upper quartile=${sdata.q3},
                        lower quartile=${sdata.q1},
                        upper whisker=${sdata.max},
                        lower whisker=${sdata.min},
                    },fill, draw=black
            ] coordinates {
            };\n`;

   }

   return code;
}

/**
 * @param {DataSet} dataSet
 * @returns {Promise<string>}
 */
async function seenExploitsWorking(dataSet) {

   stats["numSecBenchNoRefinements"] = dataSet.working.filter(s => s.runnerResult.seenExploits.length === 1).length;
   stats["numSecBenchRefinements"] = dataSet.working.length - stats["numSecBenchNoRefinements"];
   stats["numSecBenchRefinementsLessThanTen"] = dataSet.working.filter(s => s.runnerResult.seenExploits.length < 10).length - stats["numSecBenchNoRefinements"]

   let min = Infinity, max = 0;
   // Group by vulnerability type
   const refinementCoords = {};
   for (const lbl of VULNERABILITY_LABELS) {
      const attempts = dataSet.working.filter(s => s.vulnerabilityTypeLabel === lbl).map(s => s.runnerResult.seenExploits.length - 1);
      const grouped = {};
      for (const numAttempts of attempts) {
         if (numAttempts < min) {
            min = numAttempts;
         } else if (numAttempts > max) {
            max = numAttempts;
         }
         if (!grouped[numAttempts]) {
            grouped[numAttempts] = 0;
         }
         grouped[numAttempts]++;
      }
      refinementCoords[lbl] = grouped;
   }

   // init xlabels
   const xlabelsNumAttempts = [];
   for (let i = min; i <= 20; i++) {
      xlabelsNumAttempts.push(i);
   }

   let code = `
   \\begin{figure}
    \\centering
    \\pgfplotsset{width=13cm,compat=1.18}

   \\begin{tikzpicture}
    \\begin{axis}[
                xlabel = {x}, ylabel = {y},
                xlabel = {\\#Refinemements},
                ylabel = {\\#Vulnerabilities},
                cycle list/Set1-8,
                x tick style={draw=none},
                line width=1.4pt,
                axis line style={thin},
                xmin = 0, xmax = 20,
                ymin = 0, ymax = 80,
                xtick={0,1,...,20},
                legend entries={${VULNERABILITY_LABELS.map(v => VULNERABILITY_LABELS_MAP[v]).join(",")}},
                legend style={nodes=right,line width=0.5pt,cells={line width=1.4pt}}
            ]
        `
   for (const lbl of VULNERABILITY_LABELS) {
      code += `\\addplot coordinates {`;
      for (const xlabel of xlabelsNumAttempts) {
         code += `(${xlabel},${refinementCoords[lbl][xlabel] ?? 0})`;
      }
      code += `};\n`;
   }

   code += `
       
    \\end{axis}
\\end{tikzpicture}

\\caption{Number of refinements per vulnerability type for the ${dataSet.name} dataset.}
    \\label{fig:${dataSet.name}_refinements}

\\end{figure}
`;

   return code;
}

/**
 * @param {DataSet} dataSet
 * @returns {Promise<string>}
 */
async function timePieChart(dataSet) {

   const totalTime = dataSet.entries.map(s => s.getDurationFor("runner")).reduce((a, b) => a + b, 0);
   // codeql.init
   // const codeqlInitTime = dataSet.entries.map(s => s.getDurationFor("codeql.init")).reduce((a, b) => a + b, 0);
   const codeQLQuery = dataSet.entries.map(s => s.getDurationFor("codeql.analyse")).reduce((a, b) => a + b, 0);

   const llmQuery = dataSet.entries.map(s => s.getDurationFor("model.query")).reduce((a, b) => a + b, 0);

   const getExportsFromPackage = dataSet.entries.map(s => s.getDurationFor("getExportsFromPackage")).reduce((a, b) => a + b, 0);

   const percCodeQLQuery = ((codeQLQuery / totalTime) * 100).toFixed(0);
   const percLLMQuery = ((llmQuery / totalTime) * 100).toFixed(0);
   const percGetExportsFromPackage = ((getExportsFromPackage / totalTime) * 100).toFixed(0);

   return `\\begin{figure}[htp!]
   \\centering
    \\begin{tikzpicture}
        \\pie[polar]{${percCodeQLQuery}/CodeQL, ${percLLMQuery}/LLM, ${percGetExportsFromPackage}/API Exploration, ${100 - percCodeQLQuery - percLLMQuery - percGetExportsFromPackage}/Other}
    \\end{tikzpicture}
    \\caption{Average time spent on each step of the pipeline.}
    \\label{fig:time_spent}
\\end{figure}`;

}

async function constants() {

   for (const dataSet of dataSets) {
      const dsName = kebabToCamel(dataSet.name).split(".")[0]

      stats[`num${dsName}Total`] = dataSet.entries.length;
      // Only GHSA
      stats[`num${dsName}GHSA`] = dataSet.entries.filter(s => isValidGhsaId(s.advisory.id)).length;
      // Only Snyk
      stats[`num${dsName}Snyk`] = dataSet.entries.filter(s => isValidSnykId(s.advisory.id)).length;

      stats[`num${dsName}Working`] = dataSet.working.length;
      stats[`num${dsName}Failures`] = dataSet.failures.length;

      let successRate = dataSet.working.length / (dataSet.entries.length);
      stats[`successRate${dsName}`] = `${(successRate * 100).toFixed(0)}\\%`;

      stats[`timePerExploit${dsName}`] = (dataSet.durations.reduce((a, b) => {
         return a + b;
      }, 0) / 1000 / 60 / dataSet.entries.length).toFixed(0) + " minutes";
      // Now only successful
      stats[`timePerExploitSuccess${dsName}`] = (dataSet.working.map(r => r.duration).reduce((a, b) => a + b, 0) / 1000 / 60 / dataSet.working.length).toFixed(0) + " minutes";
      // Now only CodeQL
      stats[`timePerExploitCodeQL${dsName}`] = (dataSet.entries.map(r => r.durationOnlyCodeQL).reduce((a, b) => a + b, 0) / 1000 / 60 / dataSet.entries.length).toFixed(0) + " minutes";
      // Now only model
      stats[`timePerExploitLLM${dsName}`] = (dataSet.entries.map(r => r.durationOnlyLLM).reduce((a, b) => a + b, 0) / 1000 / 60 / dataSet.entries.length).toFixed(0) + " minutes";

      stats[`completionTokensAverage${dsName}`] = (dataSet.completionTokens.reduce((a, b) => a + b, 0) / dataSet.entries.length).toFixed(0);
      stats[`promptTokensAverage${dsName}`] = (dataSet.promptTokens.reduce((a, b) => a + b, 0) / dataSet.entries.length).toFixed(0);

      // Now only for working instances
      stats[`completionTokensAverageSuccess${dsName}`] = (dataSet.working.map(r => r.completionTokens).reduce((a, b) => a + b, 0) / dataSet.working.length).toFixed(0);
      stats[`promptTokensAverageSuccess${dsName}`] = (dataSet.working.map(r => r.promptTokens).reduce((a, b) => a + b, 0) / dataSet.working.length).toFixed(0);

      // Now only failing
      stats[`completionTokensAverageFailure${dsName}`] = (dataSet.failures.map(r => r.completionTokens).reduce((a, b) => a + b, 0) / dataSet.failures.length).toFixed(0);
      stats[`promptTokensAverageFailure${dsName}`] = (dataSet.failures.map(r => r.promptTokens).reduce((a, b) => a + b, 0) / dataSet.failures.length).toFixed(0);

      // Average LLM costs per exploit
      stats[`costPerExploit${dsName}`] = (dataSet.costs.reduce((a, b) => a + b, 0) / dataSet.entries.length).toFixed(2);
      // Only successful
      stats[`costPerExploitSuccess${dsName}`] = (dataSet.working.map(r => r.cost).reduce((a, b) => a + b, 0) / dataSet.working.length).toFixed(3);
      // Only failing
      stats[`costPerExploitFailure${dsName}`] = (dataSet.failures.map(r => r.cost).filter(s => isNumber(s) && !isNaN(s)).reduce((a, b) => a + b, 0) / dataSet.failures.length).toFixed(2);

      for (const label of VULNERABILITY_LABELS) {
         // success rate by vulnerability type
         const working = dataSet.entriesByVulnerabilityTypeLabel(label).filter(s => s.works());
         stats[`successRate${dsName}${kebabToCamel(label)}`] = `${(working.length / dataSet.entriesByVulnerabilityTypeLabel(label).length * 100).toFixed(0)}\\%`;
      }

      // Taint path analysis
      let sameFile = 0, sameFunction = 0;
      for (const entry of dataSet.entries) {
         if (!entry.works()) {
            continue;
         }
         const workingTaintPath = entry.runnerResult?.exploitSuccessResult?.workingTaintPath;
         if (!workingTaintPath) {
            continue;
         }
         try {
            const fileName = workingTaintPath.taintStepLocations[0].file;
            if (workingTaintPath.taintStepLocations.every(l => l.file === fileName)) {
               sameFile++;
            }
            if (workingTaintPath.functionSnippets.length === 1) {
               sameFunction++;
            }
         } catch (e) {
            // Can happen for dynamic taint paths
            console.error(entry.advisory.id)
         }
      }
      stats[`num${dsName}TaintPathSameFile`] = sameFile;
      stats[`num${dsName}TaintPathSameFunction`] = sameFunction;
   }

   let code = "";
   for (const [k, v] of Object.entries(stats)) {
      code += `\\newcommand{\\${k}}{${v}}\n`;
   }
   code = code.replaceAll("$", "\\$");
   return code;
}

/**
 * @param {DataSet} dataSet
 */
function years(dataSet) {
   dataSet.ensureAllEntriesHaveYear();

   const grouped = dataSet.groupByYear();

   const uniqueYears = Object.keys(grouped);

   let code = `\\begin{figure}
    \\centering
    \\pgfplotsset{width=16cm,compat=1.18}
    \\begin{tikzpicture}
        \\begin{axis}[
                ybar stacked,
                symbolic x coords={${uniqueYears.join(", ")}},
                xtick=data,
                ylabel={Vulnerability Count},
                xlabel={Year},
                ymin=0,
                bar width=25pt,
                enlarge x limits=0.1,
                legend style={at={(0.02,0.75)}, anchor=south west},
                cycle list/Set1-8,
            ]
           `;
   for (const vulnerabilityTypeLabel of VULNERABILITY_LABELS) {
      const withCve = dataSet.entries.filter(e => e.vulnerabilityTypeLabel === vulnerabilityTypeLabel);
      const yearCountMap = {};
      for (const year of uniqueYears) {
         yearCountMap[year] = 0;
         for (const res of withCve) {
            if (res.advisory.year + "" === year) {
               yearCountMap[year]++;
            }
         }
      }
      const coords = Object.entries(yearCountMap).map(([k, v]) => `(${k},${v})`);
      code += `\\addplot+[fill,ybar] coordinates {` + coords.join(" ") + `}; \n`
   }

   code += `\n \\legend{${VULNERABILITY_LABELS.map(v => VULNERABILITY_LABELS_MAP[v]).join("\\strut, ")}};`
   code += `
           
        \\end{axis}
    \\end{tikzpicture}
      \\caption{Distribution of vulnerabilities by type and year in the ${dataSet.name} dataset.}
      \\label{fig:${dataSet.name}_vulnerabilities_years}
   
\\end{figure}`

   return code;
}

/**
 * @param {DataSet} dataSet
 * @param {Array<string>} refinerNames
 * @returns {Promise<string>}
 */
async function genTableSuccessRateComparison(dataSet, refinerNames) {
   const advisoryIdsToInclude = [];

   // Load datatset and add advisory ids
   const explodeJsDataSet = loadExplodeJsDataSet();
   for (let explodeJsEntry of explodeJsDataSet.entries) {
      const explodeJsAdv = explodeJsEntry.advisory;

      let genpoc = secBenchDataSet.entries.filter(
         s => s.advisory.package.name === explodeJsAdv.package.name &&
            s.advisory.package.version === explodeJsAdv.package.version
      )
      if (genpoc.length === 0) {
         console.warn(`No secbench.js entry for ${explodeJsAdv.package.name}@${explodeJsAdv.package.version}`);
         continue;
      }
      if (genpoc.length > 1) {
         console.warn(`Multiple matches for ${explodeJsAdv.package.name}@${explodeJsAdv.package.version}`);
      }
      genpoc = genpoc[0];
      if (genpoc.vulnerabilityTypeLabel !== explodeJsEntry.vulnerabilityTypeLabel) {
         console.warn(`Vulnerability type mismatch for ${explodeJsAdv.package.name}@${explodeJsAdv.package.version}: ${genpoc.vulnerabilityTypeLabel} != ${explodeJsEntry.vulnerabilityTypeLabel}`);
      }
      explodeJsEntry.advisory = genpoc.advisory;
      advisoryIdsToInclude.push(genpoc.advisory.id);
   }

   const columnNames = [];
   const tableData = [];

   const explodeJsColumn = [];
   for (const label of VULNERABILITY_LABELS) {
      let l = explodeJsDataSet.working.filter(s => advisoryIdsToInclude.includes(s.advisory.id) && s.vulnerabilityTypeLabel === label);
      explodeJsColumn[label] = l.length;
   }
   tableData.push(explodeJsColumn);
   columnNames.push("ExplodeJS");

   // Now all refiners
   for (const refinerName of refinerNames) {
      const dataSetRefiner = await loadLabeledDataSet(SEC_BENCH, refinerName);

      const column = {};
      for (const label of VULNERABILITY_LABELS) {
         let l = dataSetRefiner.working.filter(s => (label === "redos" || (label !== "redos" && advisoryIdsToInclude.includes(s.advisory.id))) && s.vulnerabilityTypeLabel === label);
         column[label] = l.length;
      }
      tableData.push(column);
      columnNames.push(refinerName);
   }

   const totals = [];
   for (const td of tableData) {
      totals.push(Object.values(td).reduce((a, b) => a + b, 0));
   }

   let code = `
   \\begin{tabular}{l${"S".repeat(columnNames.length)}}
    \\toprule
          &                     & \\multicolumn{${refinerNames.length}}{c}{\\toolName}       \\\\

    CWE   & ${columnNames.map(name => `\\textit{${name}}`).join(" & ")} \\\\
    \\midrule
   `;
   // C     & 12.3                & 341.6                         & 7   \\\\
   for (const lbl of VULNERABILITY_LABELS) {
      code += `        ${VULNERABILITY_LABELS_MAP[lbl]} & `;
      /*   for (const column of rows) {
            const l = column[lbl];
            code += ` ${l} & `;
         }*/
      code += tableData.map(r => r[lbl]).join(" & ");
      // remove last &
      //code = code.slice(0, -2);

      code += `\\\\ \n`;
   }

   code += ` \\bottomrule
    Total & ${totals.join(" & ")} \\\\ \n
\\end{tabular}
   `;

   return code;
}

/**
 * @param {DataSet} dataSet
 * @param {Array<string>} refinerNames
 * @returns {Promise<string>}
 */
async function ablationStudyTable(dataSet, refinerNames) {
   let code = `\\begin{table}
    \\centering
    \\caption{The effect of \\name{} components on successfully generating PoC exploits.}
    \\label{tab:ablation}
    \\begin{tabular}{lrr}
        \\toprule
        Configuration     & Valid Exploits & Success Rate \\\\
        \\midrule
        `;

   code += `\\name{} & ${dataSet.working.length} & ${(dataSet.working.length / dataSet.entries.length * 100).toFixed(0)}\\% \\\\ \n`;

   for (const refinerName of refinerNames) {
      if (refinerName === DefaultRefiner.name) {
         continue;
      }
      const ds = await loadLabeledDataSet(dataSet.name, refinerName);
      const validExploits = ds.entries.filter(s => s.works()).length;
      const successRate = (validExploits / ds.entries.length * 100).toFixed(0) + "\\%";
      code += `${refinerLabelsMapping[refinerName]} & ${validExploits} & ${successRate} \\\\ \n`;
   }

   code += `
        \\bottomrule
    \\end{tabular}
\\end{table}`;
   return code;
}

/**
 * @param {DataSet} dataSet
 * @param {Array<string>} refinerNames
 * @returns {Promise<string>}
 */
async function ablationStudyPlots(dataSet, refinerNames) {
   let code = "";

   const defaultName = "C_{all}";

   let i = 0;
   for (const vulnerabilityTypeLabel of VULNERABILITY_LABELS) {
      /**
       * @type {{[refinerName: string]: DataSet}}
       */
      const ablationDataSets = {};
      for (const refinerName of refinerNames) {
         ablationDataSets[refinerName] = await loadLabeledDataSet(dataSet.name, refinerName);
      }
      ablationDataSets[defaultName] = dataSet;

      code += `\\begin{subfigure}{${i === 4 ? "1" : ".44"}\\textwidth}
      \\centering
        \\begin{tikzpicture}
            \\begin{axis}[
                    axis on top,
                    xtick={1,2,3,4,5,6},
                    x tick style={draw=none},
                    bar width=25pt,
                    xticklabels={${refinerNames.map(refinerName => "$" + (refinerName === DefaultRefiner.name ? defaultName : refinerName.slice(0, 2)) + "$").join(",")}},
                    xlabel={\\textit{${VULNERABILITY_LABELS_MAP[vulnerabilityTypeLabel]}}},
                    ylabel={Valid Exploits},
                    cycle list/Set1-8,
                    nodes near coords,
                ]
               ${refinerNames.map((refinerName, index) => {
         return `\\addplot+[fill,${index === 5 ? "Set1Gray," : ""}ybar] coordinates {(${index + 1},${ablationDataSets[refinerName].entriesByVulnerabilityTypeLabel(vulnerabilityTypeLabel).filter(s => s.works()).length})};`
      }).join("\n")}
      
            \\end{axis}
        \\end{tikzpicture}
    \\end{subfigure} ${i % 2 === 0 ? "\\hfill" : ""}%
    ${[1, 3].includes(i) ? "\\par\\bigskip" : ""}%
     `
      i++;
   }

   return code;
}

function packageCountCWEBench() {
   let code = `
   \\begin{table}[h]
    \\centering
    \\caption{Distribution of vulnerability types in \\dsname.}
    \\begin{tabular}{lrrr}
        \\toprule
        \\textbf{Vulnerability Class} & \\textbf{GHSA} & \\textbf{Snyk} & \\textbf{Total} \\\\
        \\midrule
        `;

   for (const lbl of VULNERABILITY_LABELS) {
      const advisoriesByLabel = cweBenchDataSet.byVulnerabilityTypeLabel(lbl);
      code += `        ${VULNERABILITY_LABELS_MAP[lbl]} &  ${advisoriesByLabel.filter(s => isValidGhsaId(s.id)).length} & ${advisoriesByLabel.filter(s => isValidSnykId(s.id)).length} & ${advisoriesByLabel.length} \\\\ \n`;
   }

   // add row total
   code += `\\midrule\n`;
   code += `Total & ${cweBenchDataSet.entries.filter(s => isValidGhsaId(s.advisory.id)).length} & ${cweBenchDataSet.entries.filter(s => isValidSnykId(s.advisory.id)).length} & ${cweBenchDataSet.entries.length} \\\\ \n`;
   code += `
        \\bottomrule
    \\end{tabular}
     \\label{tab:cwebenchjs}
\\end{table}
`

   return code;
}

/**
 * @param {DataSet} dataSet
 * @returns {Promise<string>}
 */
async function tableSuccessRate(dataSet, showLegend = true, legendRef = undefined) {
   let code = `\\pgfplotstableread[col sep=comma,header=true]{% added header row
    Vulnerability,1,2,3\n`;

   const nameData = "data";// "dataSuccessRate" + dataSet.name.replace(/[^a-zA-Z0-9]/g, "");

   for (const label of VULNERABILITY_LABELS) {
      const working = dataSet.entriesByVulnerabilityTypeLabel(label).filter(s => s.works());
      const failures = dataSet.entriesByVulnerabilityTypeLabel(label).filter(s => s.failure());
      const falsePositives = dataSet.entriesByVulnerabilityTypeLabel(label).filter(s => s.falsePositive());
      code += `${VULNERABILITY_LABELS_MAP[label]}, ${working.length}, ${failures.length}, ${falsePositives.length}\n`;
   }
   code += `}\\${nameData}

\\pgfplotstablecreatecol[
    create col/expr={
            \\thisrow{1} + \\thisrow{2} + \\thisrow{3}
        }
]{sum}{\\${nameData}}

\\pgfplotsset{
    percentage plot/.style={
            point meta=explicit,
            every node near coord/.append style={
                    font=\\tiny,
                    %color=black,
                },
            nodes near coords={
                    \\pgfmathtruncatemacro\\iszero{\\originalvalue==0}% <-- needed to remove space
                    \\ifnum\\iszero=0
                        \\pgfmathprintnumber[fixed,fixed zerofill,precision=0]{\\pgfplotspointmeta}
                    \\fi
                },
            yticklabel=\\pgfmathprintnumber{\\tick}\\,$\\%$,
            ymin=0,
            ymax=100.01, % added .01 
            visualization depends on={y \\as \\originalvalue},
            enlarge x limits={abs=6mm}
        },
    percentage series/.style={
            table/x expr=\\coordindex, %added
            table/y expr=(\\thisrow{#1}/\\thisrow{sum}*100),
            table/meta=#1
        }
}

    \\begin{tikzpicture}
        \\begin{axis}[
                ybar stacked,
                percentage plot,
                bar width=1cm,
                xticklabels from table={\\${nameData}}{Vulnerability},${legendRef ? `legend to name={${legendRef}},` : ""},
                xtick=${nameData},
                x tick label style={
                        rotate=45,
                        anchor=east,
                        xshift=-1.5mm, yshift=-2mm
                    },
                legend style={
                        at={(0.5,-0.45)},
                        anchor=south,
                        legend columns=-1
                    },
            ]

            \\addplot [fill=Set1Green]   table[percentage series=1] {\\${nameData}};
            \\addplot [fill=Set1Red]  table[percentage series=2] {\\${nameData}};
            \\addplot [fill=Set1Blue]                 table[percentage series=3] {\\${nameData}};

            \\addplot [forget plot,nodes near coords align=above] table[x expr=\\coordindex,y expr=0.0001,meta=sum]{\\${nameData}};

            ${showLegend ? `\\legend{\\strut Success, \\strut Failure, \\strut False Positive}` : ""}
        \\end{axis}
    \\end{tikzpicture}
    `

   return code;
}

const secBenchDataSet = await loadLabeledDataSet(SEC_BENCH);
for (const entry of loadRunnerResultsVulnIds(secBenchDataSet.advisoryIds, DefaultRefiner.name, join(RESULTS_DIR, SEC_BENCH))) {
   const dsEntry = secBenchDataSet.entries.find(e => e.advisory.id === entry.advisory.id);
   dsEntry.runnerResult = entry;
}

for (const entry of secBenchDataSet.entries) {
   if (!entry.runnerResult) {
      console.log(`No runner result for secbench ${entry.advisory.id}`);
   }
}

const cweBenchDataSet = await loadLabeledDataSet(CWE_BENCH);
for (const entry of loadRunnerResultsVulnIds(cweBenchDataSet.advisoryIds, DefaultRefiner.name, join(RESULTS_DIR, CWE_BENCH))) {
   const dsEntry = cweBenchDataSet.entries.find(e => e.advisory.id === entry.advisory.id);
   dsEntry.runnerResult = entry;
}

for (const entry of cweBenchDataSet.entries) {
   if (!entry.runnerResult) {
      console.log(`No runner result for cwe ${entry.advisory.id}`);
   }
}

const dataSets = [secBenchDataSet, cweBenchDataSet];

for (const dataSet of dataSets) {
   for (const entry of dataSet.entries) {
      if (entry.runnerResult.finished === false) {
         // Timeout 1 hour
         entry.runnerResult.performanceTracker["runner"] = [{duration: 60 * 60 * 1000}];
      }
      if (!entry.runnerResult.performanceTracker["runner"]) {
         console.warn(`No runner performance tracker for ${entry.runnerResult.advisory.id}`);
         entry.runnerResult.performanceTracker["runner"] = [{duration: 0}];
      }

      // Account for a bug in the runner. Only apply this for non-working exploits
      if (!entry.works() && entry.runnerResult.model?.totalPromptTokens > MAX_PROMPT_TOKENS) {
         entry.runnerResult.model.totalPromptTokens = MAX_PROMPT_TOKENS;
      }
      if (!entry.works() && entry.runnerResult.model?.totalCompletionTokens > MAX_COMPLETION_TOKENS) {
         entry.runnerResult.model.totalCompletionTokens = MAX_COMPLETION_TOKENS;
      }

      if (isNaN(entry.cost)) {
         console.log(`Invalid cost for ${dataSet.name}/${entry.advisory.id}`);
      }
   }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {

   let code = years(cweBenchDataSet);
   fs.writeFileSync(join(FIGURES_DIR, `${cweBenchDataSet.name}_years.tex`), code);

   code = packageCountCWEBench();
   fs.writeFileSync(join(FIGURES_DIR, "package_counts_eval.tex"), code);

   code = await tableSuccessRate(secBenchDataSet);
   fs.writeFileSync(join(FIGURES_DIR, secBenchDataSet.name + "_tables.tex"), code);

   code = await tableSuccessRate(cweBenchDataSet);
   fs.writeFileSync(join(FIGURES_DIR, cweBenchDataSet.name + "_tables.tex"), code);

   // Compute new datasets knowledge cutoff
   const before = new DataSet(cweBenchDataSet.name);
   before.entries = cweBenchDataSet.entries.filter(s => s.date <= CUT_OFF_DATE);

   const after = new DataSet(cweBenchDataSet.name);
   after.entries = cweBenchDataSet.entries.filter(s => s.date > CUT_OFF_DATE);

   stats["numCWEBenchPastKnowledgeCutoff"] = after.entries.length;

   code = await tableSuccessRate(before, true, "legendSuccessTableComparison");
   fs.writeFileSync(join(FIGURES_DIR, before.name + "_before_tables.tex"), code);

   code = await tableSuccessRate(after, false);
   fs.writeFileSync(join(FIGURES_DIR, after.name + "_after_tables.tex"), code);

   const refiners = (await loadRefiners()); // .filter(r => r.default.name !== DefaultRefiner.name);
   let refinerNames = refiners.map(r => r.default.name);

   refinerNames = [DefaultRefiner.name, "C6Refiner", "C7Refiner", "C8Refiner"]

   refinerNames = [DefaultRefiner.name, ...Object.keys(refinerLabelsMapping)]
   code = await ablationStudyTable(secBenchDataSet, refinerNames);
   fs.writeFileSync(join(FIGURES_DIR, "rq2_table.tex"), code);

   code = await ablationStudyPlots(secBenchDataSet, refinerNames);
   fs.writeFileSync(join(FIGURES_DIR, "rq2_plots.tex"), code);

   code = await genTableSuccessRateComparison(secBenchDataSet, refinerNames);
   fs.writeFileSync(join(FIGURES_DIR, "success_rates_comparison.tex"), code);

   for (const dataSet of dataSets) {
      code = boxPlot(dataSet, s => s.cost);
      fs.writeFileSync(join(FIGURES_DIR, `${dataSet.name}_costs.tex`), code);

      code = boxPlot(dataSet, s => s.duration);
      fs.writeFileSync(join(FIGURES_DIR, `${dataSet.name}_duration.tex`), code);

      code = boxPlot(dataSet, s => s.completionTokens);
      fs.writeFileSync(join(FIGURES_DIR, `${dataSet.name}_completion_tokens.tex`), code);

      code = boxPlot(dataSet, s => s.promptTokens);
      fs.writeFileSync(join(FIGURES_DIR, `${dataSet.name}_prompt_tokens.tex`), code);
   }

   code = await timePieChart(secBenchDataSet);
   fs.writeFileSync(join(FIGURES_DIR, "time_pie_chart.tex"), code);

   code = await seenExploitsWorking(secBenchDataSet);
   fs.writeFileSync(join(FIGURES_DIR, "seen_exploits.tex"), code);

   code = await constants()
   fs.writeFileSync(join(FIGURES_DIR, "constants.tex"), code);

}

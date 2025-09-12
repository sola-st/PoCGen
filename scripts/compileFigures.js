import {DATASET_NAMES, FIGURES_DIR, FIGURES_REPO_DIR} from "./constants.js";
import {join} from "node:path";
import fs from "node:fs";
import * as os from "node:os";
import {spawnSync} from "child_process";

for (const dataSetName of DATASET_NAMES) {
   const contents = fs.readFileSync(join(FIGURES_DIR, `${dataSetName}_tables.tex`), "utf-8");

   const tex = `\\documentclass{standalone} 
\\usepackage{pgfplots}
\\usepackage{xcolor}
\\usepackage{pgfplotstable}

\\definecolor{Set1Red}{HTML}{e41a1c}
\\definecolor{Set1Blue}{HTML}{377eb8}
\\definecolor{Set1Green}{HTML}{4daf4a}

\\pgfplotsset{width=13cm,compat=1.18}


\\begin{document}

${contents}

\\end{document}
`
   // tmp file
   const tempDir = os.tmpdir();
   const outFile = join(tempDir, 't.tex');
   const pdfFile = join(tempDir, 't.pdf');
   fs.writeFileSync(outFile, tex);
   spawnSync("pdflatex", ["-interaction=nonstopmode", outFile], {
      stdio: "inherit",
      cwd: tempDir,
   });
   // Transform pdf to png  pdftoppm -png
   const pngFile = join(FIGURES_REPO_DIR, `${dataSetName}_tables`);
   const buf = spawnSync("pdftoppm", ["-png", pdfFile], {
      stdio: "pipe",
   });
   // redirect buf to png
   fs.writeFileSync(pngFile + ".png", buf.stdout);
   console.log(buf.stderr.toString());
}

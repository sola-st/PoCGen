import {join} from "path";
import fs from "fs";
import {renderTemplate} from "../prompting/promptGenerator.js";
import {TEMPLATES_DIR} from "../analysis/codeql/codeQLQueryBuilder.js";

/**
 * Creates a test file for the given source and exploit.
 *
 * @param {RunnerResult} runner - The runner that is creating the test file.
 * @param {TaintPath} taintPath - The source for which to create the test file.
 * @param {string} exploit - The exploit code to include in the test file.
 * @returns {string|undefined} - The path to the created test file or undefined if an error occurred.
 */
export default function createTestFile(runner, taintPath, exploit) {
   try {
      const vars = {
         exploit,
         vulnerabilityType: taintPath.vulnerabilityType,
         package: runner.package,
         advisoryId: runner.advisory.id,
         source: {
            callable: {
               location: taintPath.source.callable.location,
            },
         },
         nmPath: runner.nmPath,
         validate: taintPath.vulnerabilityType.validate.toString(),
      };
      const outPath = join(runner.baseDir, "test.js");
      fs.writeFileSync(
         outPath,
         renderTemplate(
            join(TEMPLATES_DIR, "test.hbs"),
            vars,
         ),
      );
      console.success(`Created test case at ${outPath}`);
      return outPath;
   } catch (e) {
      console.warn(`Error while creating test file: ${e}`);
      return undefined;
   }
}

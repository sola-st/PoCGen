import {cleanFs, extractSourceCode, getZipFileList, md5,} from "../../utils/utils.js";
import {existsSync, mkdirSync, readFileSync, writeFileSync} from "node:fs";
import {join, relative} from "node:path";
import {spawnSync} from "node:child_process";
import SarifFile from "./sarif.js";
import LocationRange from "../../models/locationRange.js";
import PotentialSink from "./potentialSink.js";
import {getLocationsPredicate, getPredicate, getSourcePredicate, TEMPLATES_CODEQL_DIR,} from "./codeQLQueryBuilder.js";
import * as parser from "@babel/parser";
import {parseExpression} from "@babel/parser";
import {TSServer} from "../language-server/TSServer.js";
import {getAllFunctions, getEnclosingStatement} from "../../utils/parserUtils.js";
import {renderTemplate} from "../../prompting/promptGenerator.js";

export class FileNotIndexedError extends Error {
   constructor(filePath) {
      super(`File ${JSON.stringify(filePath)} not found in codeql database.`);
   }
}

const DB_DIR_NAME = "codeql_db";

const QL_PACK = `---
name: javascript-queries/q
version: 1.0.1
library: false
dependencies:
  codeql/javascript-all: "*"`;

// https://github.com/github/codeql/blob/d658ef1dcdd0d57e0606417a9cdb61f464b4400e/javascript/extractor/src/com/semmle/js/extractor/AutoBuild.java
export const LGTM_ENV = {
   LGTM_INDEX_FILTERS: [
      "include:**/*.js",
      "include:**/*.mjs",
      "include:**/*.cjs",
   ].join("\n"),
   LGTM_INDEX_TYPESCRIPT: "none",
};

/**
 * @typedef {import("@babel/traverse").Node} Node
 * @typedef {import("@babel/traverse").NodePath} NodePath
 * @typedef {import("@babel/types").File} BabelFile
 * @typedef {import("../../models/locationRange").default} LocationRange
 * @typedef {import("../../models/source").default} Source
 */
export default class CodeQLDatabase {
   /**
    * Cache for file contents.
    * @type {Object.<string, string>}
    */
   fileCache = {};

   /**
    * Cache for parsed files.
    * @type {Object.<string, ParseResult<BabelFile>>}
    */
   parseCache = {};

   /**
    * List of files in the CodeQL database.
    * @type {string[]}
    */
   dbFiles = [];

   /**
    * TypeScript server instance.
    * @type {TSServer}
    */
   #tsServer;

   /**
    * Cache for language server queries.
    * @type {Object.<string, LocationRange[]>}
    */
   languageServerCache = {};

   /**
    * Maximum number of paths to produce for each alert with paths.
    * @see {@link https://docs.github.com/en/code-security/codeql-cli/codeql-cli-manual/database-analyze#--max-pathsmaxpaths}
    * @type {number}
    */
   maxPaths = 5;

   /**
    * Creates an instance of CodeQLDatabase.
    * @param {string} baseDir - The base directory for the CodeQL database.
    * @param {string} srcRoot - The source root directory. In the analysis we include the entire node_modules directory.
    * @param {NpmPackage} npmPackage - The npm package.
    * @param {object} [procOpts] - Optional process options.
    */
   constructor(baseDir, srcRoot, npmPackage, procOpts = undefined) {
      const projectDir = join(srcRoot, npmPackage.asPath());
      if (!existsSync(projectDir)) {
         throw new Error(`Could not find project directory at ${projectDir}`);
      }
      this.baseDir = baseDir;
      this.procOpts = procOpts;
      this.srcRoot = srcRoot;
      this.npmPackage = npmPackage;
      this.dbDir = join(this.baseDir, DB_DIR_NAME);
      this.queryDir = join(this.baseDir, "queries");
   }

   async init() {
      if (!existsSync(join(this.dbDir, "src.zip"))) {
         const args = [
            "database",
            "create",
            "--overwrite",
            "-v",
            "--source-root",
            this.srcRoot,
            "--language=javascript",
            this.dbDir,
         ];
         console.info(`Preparing codeql database: ${args.join(" ")}`);
         const result = spawnSync(
            "codeql",
            args,
            {
               cwd: this.baseDir,
               stdio: "pipe",
               env: {
                  PATH: process.env.PATH,
                  ...LGTM_ENV,
               },
            },
         );
         if (result.status !== 0) {
            throw new Error(`Could not create codeql database:\n${result.stderr}`);
         }
      } else {
         console.info(`Reusing existing codeql database`);
      }
      const zipFiles = await getZipFileList(join(this.dbDir, "src.zip"));
      this.dbFiles = zipFiles
         .filter((path) => path.startsWith(this.srcRoot + "/"))
         .map((path) => path.substring(this.srcRoot.length + 1));
      if (this.dbFiles.length === 0) {
         throw new Error(`No files found in codeql database`);
      }
      return this.dbDir;
   }

   /**
    * @param {Source} sink
    * @param {Source[]} exportedSources
    * @returns {SarifFile}
    */
   getCGA(sink, exportedSources) {
      const query = renderTemplate(join(TEMPLATES_CODEQL_DIR, "cga.ql"), {
         SINK_PREDICATE: getLocationsPredicate([sink.callable.location]),
      });
      const fileNamePrefix = `cga_${cleanFs(sink.callable.name)}`;
      const sarifOut = this.runQuery(query, fileNamePrefix);
      const sarif = SarifFile.parseSarif(this, exportedSources, sarifOut, []);
      for (const tp of sarif.taintPaths) {
         if (tp.source) {
            continue;
         }
         const matchingSource = exportedSources.find((source) =>
               LocationRange.contains(source.callable.location, tp.taintStepLocations[0])
               || LocationRange.contains(tp.taintStepLocations[0], source.callable.location)
            ,
         );
         if (matchingSource) {
            tp.source = matchingSource;
         }
      }

      return sarif;
   }

   /*
   /!**
    * @param {Source[]} sources
    * @param {Source} sink
    * @returns {SarifFile}
    *!/
   getCGA(sources, sink) {
      this.checkSourcesIndexed(sources);
      const query = renderTemplate(join(TEMPLATES_CODEQL_DIR, "cga.ql"), {
         SOURCE_PREDICATE: getLocationsPredicate(sources.map(s => s.callable.location)),
         SINK_PREDICATE: getLocationsPredicate([sink.callable.location]),
      });
      const fileNamePrefix = `cga_${cleanFs(sink.callable.name)}`;
      const sarifOut = this.runQuery(query, fileNamePrefix);
      return SarifFile.parseSarif(this, sources, sarifOut, []);
   }*/

   /**
    * Analyzes the given sources for the specified vulnerability type.
    *
    * @param {CodeQLQueryBuilder} queryBuilder - The sources to analyze.
    * @param {Source[]} [sources] - The sources to map.
    * @returns {SarifFile} - The parsed result of the analysis.
    */
   analyse(
      queryBuilder,
      sources = undefined
   ) {
      this.checkSourcesIndexed(queryBuilder.sources);

      const sortedSources = queryBuilder.getSortedSources();
      let fileNamePrefix;
      if (sortedSources.length > 0) {
         fileNamePrefix = `${cleanFs(sortedSources.map((s) => s.name).join("_"))}`;
      } else {
         fileNamePrefix = `sources`;
      }
      const sarifOut = this.runQuery(queryBuilder.getQuery(), fileNamePrefix);
      return SarifFile.parseSarif(this, sources ?? queryBuilder.getSortedSources(), sarifOut, queryBuilder.extraSinks);
   }

   /**
    * @param {SarifFile} sarif
    * @returns {PotentialSink[]}
    */
   parsePotentialSinksSarif(sarif) {
      const potentialSinks = [];
      for (const result of sarif.runs[0].results) {
         const {physicalLocation} = result.locations[0];
         const location = LocationRange.fromCodeQL(physicalLocation);
         const src = this.extractSourceCode(location);
         let locationCallee;
         try {
            const callExpression = parseExpression(src, {
               sourceFilename: location.filePath,
               startColumn: location.startColumn,
               startLine: location.startLine,
            });
            locationCallee = LocationRange.fromBabelNode(
               callExpression.callee?.property ?? callExpression.callee,
            );
         } catch (e) {
            console.warn(`Could not parse source code as callExpression`);
            console.error(e);
         }
         potentialSinks.push(new PotentialSink(location, locationCallee, src));
      }
      return potentialSinks;
   }

   /**
    * @param {Source[]} sources
    * @param {Source} sink
    * @returns {SarifFile}
    */
   analyseStaticSinks(sources, sink) {
      this.checkSourcesIndexed(sources);
      const query = renderTemplate(join("staticSinks.ql", TEMPLATES_CODEQL_DIR), {
         FUNCTION_PREDICATE: getLocationsPredicate(sources.map(s => s.callable.location)),
         SOURCE_PREDICATE: getSourcePredicate(),
         SINK_PREDICATE: getPredicate(sink),
      });
      const sarifOut = this.runQuery(query, null);
      return SarifFile.parseSarif(this, sources, sarifOut, []);
   }

   /**
    * @param {string} query
    * @param {string} fileNamePrefix
    * @returns {string} - path to the sarif file
    */
   runQuery(query, fileNamePrefix) {
      let cKey = `${fileNamePrefix}_${md5(query)}`;
      if (`${cKey}.sarif`.length > 255) {
         cKey = md5(cKey);
      }
      const sarifOut = `${this.baseDir}/${cKey}.sarif`;
      if (existsSync(sarifOut)) {
         console.info(`Found ${sarifOut}, skipping analysis`);
         return sarifOut;
      }
      const queryFile = join(this.queryDir, `${cKey}.ql`);
      mkdirSync(this.queryDir, {recursive: true});
      writeFileSync(queryFile, query);

      writeFileSync(`${this.baseDir}/qlpack.yml`, QL_PACK);
      const result = spawnSync(
         "codeql",
         [
            "database",
            "analyze",
            "--max-paths",
            this.maxPaths,
            "-v",
            "-j10",
            "--ram",
            "8192",
            "--format",
            "sarif-latest",
            "--output",
            sarifOut,
            this.dbDir,
            queryFile,
         ],
         {
            ...this.procOpts,
            env: {
               PATH: process.env.PATH,
            },
         },
      );
      if (result.status !== 0 || !existsSync(sarifOut)) {
         const err = result.stderr?.toString();
         if (err) {
            throw new Error(`Analysing codeql database failed: ${err}`);
         }
         throw new Error(`Analysing codeql database failed`);
      }
      return sarifOut;
   }

   /**
    * @param {string} filePath
    * @returns {boolean}
    */
   isIndexed(filePath) {
      if (filePath.startsWith(this.srcRoot)) {
         filePath = relative(this.srcRoot, filePath);
      }
      return this.dbFiles.includes(filePath);
   }

   /**
    * @param {Source[]} sources
    * @throws {FileNotIndexedError} - if a source file is not indexed in the codeql database
    */
   checkSourcesIndexed(sources) {
      if (!sources) {
         return;
      }
      for (const source of sources) {
         const relativePath = source.callable.location.filePath;
         if (
            !relativePath ||
            relativePath.startsWith("/") ||
            !existsSync(join(this.srcRoot, relativePath))
         ) {
            throw new Error(`Invalid relative path: ${relativePath}`);
         }
         if (!this.dbFiles.includes(relativePath)) {
            throw new FileNotIndexedError(relativePath);
         }
      }
   }

   /**
    * Parses a file from the source root.
    *
    * @param {string} relativePath - The relative path to the file from the source root.
    * @returns {ParseResult<BabelFile>} - The parsed result of the file.
    * @throws {FileNotIndexedError} - If the file does not exist in the source root.
    */
   parse(relativePath) {
      if (!this.parseCache[relativePath]) {
         const fileContent = this.readFile(relativePath);
         this.parseCache[relativePath] = parser.parse(fileContent, {
            sourceFilename: relativePath,
            errorRecovery: true,
         });
         if (this.parseCache[relativePath].errors?.length) {
            console.warn(
               `Ignored error when parsing ${relativePath}: ${this.parseCache[relativePath].errors.map((s) => s.message)}`,
            );
         }
      }
      return this.parseCache[relativePath];
   }

   /**
    * Retrieve file from the source root.
    * If the file is not cached, it reads the file content from the disk and caches it.
    *
    * @param {string} relativePath - The relative path to the file from the source root.
    * @returns {string} - The content of the file.
    * @throws {FileNotIndexedError} - If the file does not exist in the source root.
    */
   readFile(relativePath) {
      if (relativePath.startsWith(this.srcRoot)) {
         relativePath = relative(this.srcRoot, relativePath);
      }
      if (!this.fileCache[relativePath]) {
         const absPath = join(this.srcRoot, relativePath);
         if (!existsSync(absPath)) {
            throw new FileNotIndexedError(relativePath);
         }
         this.fileCache[relativePath] = readFileSync(absPath, "utf8");
      }
      return this.fileCache[relativePath];
   }

   /**
    * @param {Node} node - babel node
    * @returns {string}
    */
   extractSourceCodeNode(node) {
      return this.extractSourceCode(LocationRange.fromBabelNode(node));
   }

   /**
    * @param {LocationRange} locationRange
    * @returns {string}
    * @throws {Error} - if file does not exist in database
    */
   extractSourceCode(locationRange) {
      const fileContent = this.readFile(locationRange.filePath);
      return extractSourceCode(locationRange, fileContent);
   }

   /**
    * @param {string} filePath
    * @param {number} line - 0-based
    * @param {number} contextLines
    * @returns {string}
    */
   getFileLine(filePath, line, contextLines = 0) {
      const fileLines = this.readFile(filePath).split("\n");
      const start = Math.max(0, line - contextLines);
      const end = Math.min(fileLines.length, line + contextLines + 1);
      return fileLines.slice(start, end).join("\n");
   }

   /**
    * @returns {Promise<TSServer>}
    */
   async getTSServer() {
      if (!this.#tsServer) {
         this.#tsServer = new TSServer(this.srcRoot);
         await this.#tsServer.init();
      }
      return this.#tsServer;
   }

   /**
    * Query language server
    * @param {Location} location
    * @param {function} queryFn
    * @returns {Promise<LocationRange[]>}
    */
   async query(location, queryFn) {
      const relPath = location.filePath;
      const cKey = `${queryFn.name}_${location.toString()}`;
      if (!(cKey in this.languageServerCache)) {
         const absPath = join(this.srcRoot, relPath);
         if (!existsSync(absPath)) {
            throw new Error(`File ${relPath} does not exist`);
         }
         const tsServer = await this.getTSServer();
         const locations = await queryFn.apply(tsServer, [location]); // Translate absolute paths to relative
         for (const loc of locations) {
            if (loc.filePath.startsWith(this.srcRoot)) {
               loc.filePath = relative(this.srcRoot, loc.filePath);
            }
         }

         this.languageServerCache[cKey] = locations;
      }
      return this.languageServerCache[cKey];
   }

   /**
    * @param {Location} location
    * @returns {Promise<LocationRange[]>}
    */
   async getDefinitions(location) {
      return this.query(location, TSServer.prototype.getDefinitions);
   }

   /**
    * @param {Location} location
    * @returns {Promise<LocationRange[]>}
    */
   async getReferences(location) {
      return this.query(location, TSServer.prototype.getReferences);
   }

   /**
    * @param {LocationRange} locationRange
    * @returns {NodePath}
    */
   getEnclosingFunction(locationRange) {
      const functions = getAllFunctions(this.parse(locationRange.filePath));
      return functions.findLast((f) => LocationRange.fromBabelNode(f.node).contains(locationRange));
   }

   /**
    * @param {LocationRange} locationRange
    * @returns {NodePath}
    */
   getEnclosingStatement(locationRange) {
      const ast = this.parse(locationRange.filePath);
      return getEnclosingStatement(ast, locationRange);
   }

   /**
    * @param {NodePath} nodePath
    * @returns {NodePath|null}
    */
   findOutermostCallExpression(nodePath) {
      // Check children
      let callExpression = null;
      nodePath.traverse({
         CallExpression(path) {
            callExpression = path;
            path.stop();
         }
      });

      return callExpression;
   }

   async stop() {
      if (this.#tsServer) {
         await this.#tsServer.stop();
      }
   }

}

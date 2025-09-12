import { createRequire } from "module";
import axios from "axios";

import Database from "better-sqlite3";
import { join } from "node:path";
import async from "async";
import {
  calculateInstalledVersion,
  findMatchingVersion,
  getVersions,
  REGISTRY_BASE_URL,
} from "./npmUtils.js";

const require = createRequire(import.meta.url);

// https://www.npmjs.com/browse/depended/execa?offset=0&limitx"=1

export default class NpmDependencies {
  constructor(outputDir) {
    const dbPath = join(outputDir, "packages.db");
    console.log(`Using database at ${dbPath}`);
    this.db = new Database(dbPath, {});
    this.db.pragma("journal_mode = WAL");
    this.db
      .prepare(
        `
      CREATE TABLE IF NOT EXISTS dependencies (
          name TEXT NOT NULL,
          version TEXT NOT NULL,
          downstreamPackageName TEXT NOT NULL,
          downstreamPackageSemVer TEXT NOT NULL,
          PRIMARY KEY (name, version, downstreamPackageName, downstreamPackageSemVer)
      )
    `,
      )
      .run();
  }

  async saveToDatabase(metadata) {
    const insert = this.db.prepare(
      "INSERT OR IGNORE INTO dependencies VALUES (?, ?, ?, ?)",
    );
    for (const dependency in metadata.dependencies) {
      insert.run(
        metadata.name,
        metadata.version,
        dependency,
        metadata.dependencies[dependency],
      );
    }
  }

  async downloadPackage(packageName, version) {
    try {
      const metadata = await this.getMetaDataFromApi(packageName, version);
      await this.saveToDatabase(metadata);
      // console.log(`Downloaded metadata for "${packageName}:${version}"`);
    } catch (error) {
      throw `Error downloading package "${packageName}:${version}": ${error}`;
    }
  }

  async downloadAll(packageNames) {
    console.info(`Downloading metadata for ${packageNames.length} packages`);
    const queue = async.queue(async (packageName) => {
      try {
        await this.downloadPackage(packageName, "latest");
      } catch (error) {
        console.error(error);
      }
    }, 1);
    packageNames.forEach((p) => queue.push(p));
    await queue.drain();
  }

  /**
   * @returns {String[]}
   */
  getPackageNames() {
    return require("all-the-package-names");
  }

  /**
   * Return a list of packages that are upstream of the given package
   * @param {string} downstreamPackageName - name of the package
   * @param {string[]} downstreamPackageVVR - vulnerable version range
   * @returns {Promise<*[]>}
   */
  async getUpstreamPackages(downstreamPackageName, downstreamPackageVVR) {
    const select = this.db.prepare(
      "SELECT name, version, downstreamPackageSemVer FROM dependencies WHERE downstreamPackageName = ?",
    );
    const rows = select.all(downstreamPackageName);
    console.info(`Found ${rows.length} upstream packages, checking versions`);
    const result = [];
    for (const row of rows) {
      // Determine whether the version npm installs matches the semver
      const installedVersion = await calculateInstalledVersion(
        downstreamPackageName,
        row.downstreamPackageSemVer,
      );
      const allVersions = await getVersions(downstreamPackageName);
      if (
        findMatchingVersion(allVersions, downstreamPackageVVR).includes(
          installedVersion,
        )
      ) {
        console.info(
          `Package "${row.name}" is upstream of "${downstreamPackageName}"`,
        );
        result.push(row);
      }
    }
    return result;
  }

  async getMetaDataFromApi(packageName, version) {
    const response = await axios.get(
      `${REGISTRY_BASE_URL}/${packageName}/${version}`,
    );
    const json = response.data;
    return {
      name: json.name,
      version: json.version,
      latestVersion: json.version,
      dependencies: json.dependencies,
    };
  }
}

(async () => {
  try {
    const npm = new NpmDependencies(process.cwd());
    await npm.downloadAll(npm.getPackageNames());
  } catch (e) {
    console.log(e);
  }
})();

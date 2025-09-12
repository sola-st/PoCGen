import {spawnSync} from "child_process";
import semver from "semver";
import axios from "axios";

export const REGISTRY_BASE_URL = "https://registry.npmjs.org";

function splitOnFirstDigit(input) {
   const match = input.match(/^(\D*)(\d)(.*)$/);
   if (match) {
      return [match[1], match[2] + match[3]];
   }
   return [input];
}

export function getVersionsCli(packageName) {
   const allVersions = JSON.parse(
      spawnSync("npm", [
         "show",
         packageName,
         "versions",
         "--json",
      ]).stdout.toString(),
   );
   if (allVersions.error) {
      throw new Error(
         `Error fetching versions for ${packageName}: ${allVersions.error?.summary}`,
      );
   }
   return allVersions;
}

/**
 * @param packageName
 * @param versionRange
 * @returns {Promise<string|null>}
 */
export async function calculateInstalledVersion(packageName, versionRange) {
   const availableVersions = await getVersions(packageName);
   if (availableVersions.length === 0) {
      console.error("No versions available for this package");
      return null;
   }
   const validVersion = semver.maxSatisfying(availableVersions, versionRange);
   if (validVersion) {
      return validVersion;
   }
   if (versionRange === "latest") {
      return availableVersions.pop();
   }
   return null;
}

export async function getVersions(packageName) {
   const response = await axios.get(`${REGISTRY_BASE_URL}/${packageName}`);
   const json = response.data;
   if (!json.versions) {
      throw new Error(`No versions found for ${packageName}`);
   }
   return Object.keys(json.versions);
}

/**
 * Get the minimum version that satisfies the given version range
 * @param {string} packageName
 * @param {string[]} vvr - vulnerable version range
 * @returns {Promise<*|string>} - latest version that satisfies the given version range
 */
export async function getMatchingPackageVersion(packageName, vvr) {
   const allVersions = await getVersions(packageName);
   const matchingVersions = findMatchingVersion(allVersions, vvr);
   if (matchingVersions.length === 0) {
      throw new Error(
         `No version found for ${packageName} that satisfies "${vvr}". Versions:\n${allVersions}`,
      );
   }
   return matchingVersions[matchingVersions.length - 1];
}

/**
 * @param {string[]} allVersions
 * @param {string[]} vvr
 * @returns {string[]} - versions that satisfy the given version range
 */
export function findMatchingVersion(allVersions, vvr) {
   if (!(vvr instanceof Array)) {
      throw new Error(`Invalid type for version range: ${vvr}`);
   }
   if (vvr.includes("*")) {
      return allVersions;
   }
   const versionExpr = [];
   for (const version of vvr) {
      if (semver.validRange(version) === null) {
         throw new Error(`Invalid version: "${version}"`);
      }
      versionExpr.push(new semver.Range(version));
   }

   const satisfiesAny = function (version) {
      return versionExpr.some((range) => {
         return range.test(version);
      });
   };
   const result = [];
   allVersions = allVersions.map((v) => semver.parse(v));
   for (const version of allVersions) {
      if (satisfiesAny(version)) {
         result.push(version.raw);
      }
   }
   return result;
}

/**
 * Get the minimum version that satisfies the given version range
 * @param {string[]} allVersions
 * @param {string[]} vvr
 * @returns {string|null}
 */
export function findMinPackageVersion(allVersions, vvr) {
   // Extra case for "*"
   if (vvr.includes("*")) {
      // All versions are vulnerable, pick latest
      return allVersions[allVersions.length - 1];
   }

   const versionExpr = [];
   for (const expr of vvr) {
      const [op, version] = splitOnFirstDigit(expr);
      const v = semver.parse(version);
      if (v === null) {
         throw new Error(`Invalid version: ${version}`);
      }
      versionExpr.push([op, v]);
   }

   const satisfies = function (version) {
      return versionExpr.every(([op, v]) => {
         //return semver.satisfies(version, v);
         (op === ">=" && semver.gte(version, v)) ||
         (op === "<=" && semver.lte(version, v)) ||
         (op === "<" && semver.lt(version, v)) ||
         (op === ">" && semver.gt(version, v)) ||
         (op === "=" && semver.eq(version, v)) ||
         (op === "~" && semver.satisfies(version, `~${v}`));
      });
   };
   allVersions = allVersions.reverse().map((v) => semver.parse(v));
   for (const version of allVersions) {
      if (satisfies(version)) {
         return version.raw;
      }
   }
   return null;
}

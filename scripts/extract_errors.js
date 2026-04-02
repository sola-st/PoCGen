import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function findErrorKeys(data, keysFound) {
    if (data === null || data === undefined) return;

    if (typeof data === 'object') {
        if (Array.isArray(data)) {
            for (const item of data) {
                findErrorKeys(item, keysFound);
            }
        } else {
            for (const key in data) {
                if (key.toLowerCase() === 'errors' || key.toLowerCase() === 'error') {
                    keysFound.push({
                        value: data[key]
                    });
                }
                findErrorKeys(data[key], keysFound);
            }
        }
    }
}

function main() {
    const rootDir = path.resolve(__dirname, '..');
    const outputDir = path.join(rootDir, 'output');

    let files;
    try {
        files = fs.readdirSync(outputDir);
    } catch (e) {
        console.error("Could not read output directory:", e);
        return;
    }

    const logFiles = files.filter(f => f.startsWith('DefaultRefiner_pipeline_') && f.endsWith('.json'));
    const allErrors = [];
    let totalItems = 0;
    let all_IDs = new Set();
    let in_output = new Set();

    for (const file of logFiles) {
        const filePath = path.join(outputDir, file);
        let content;
        try {
            const raw = fs.readFileSync(filePath, 'utf8');
            content = JSON.parse(raw);
        } catch (e) {
            console.error(`Failed to read or parse ${file}:`, e);
            continue;
        }

        // Print stats on how many items are there
        totalItems += Object.keys(content).length;

        for (const [itemId, itemData] of Object.entries(content)) {
            all_IDs.add(itemId);
            // Check if exploitSuccessResult is present and non-null
            // The request says: "find the items ... that do not have a non-null 'exploitSuccessResult'"
            // So if exploitSuccessResult is NOT null (meaning it is an object/true), we skip.
            // If it is null or undefined, we process.

            if (itemData && itemData.exploitSuccessResult !== null && itemData.exploitSuccessResult !== undefined) {
                // Add as a successful item
                allErrors.push({
                    file: file,
                    id: itemId,
                    value: "Success"
                });
                in_output.add(itemId);
                continue;
            }

            const found = [];
            findErrorKeys(itemData, found);

            if (found.length > 0) {
                for (const err of found) {
                    if (err.value === null || err.value === undefined || (err.value.hasOwnProperty('length') && err.value.length === 0)) {
                        continue;
                    }

                    if (err.value instanceof Array) {
                        err.value = [...new Set(err.value)];
                    } else {
                        err.value = [...new Set([err.value])];
                    }

                    let existing = allErrors.find(e => e.file === file && e.id === itemId);
                    if (existing && existing.value instanceof Array) {
                        for (const value of err.value) {
                            for (const existingValue of existing.value) {
                                if (JSON.stringify(existingValue) === JSON.stringify(value)) {
                                    continue;
                                }
                            }
                            existing.value.push(value);
                        }
                        continue;
                    } else if (existing) {
                        existing.value = [existing.value];
                        for (const value of err.value) {
                            for (const existingValue of existing.value) {
                                if (JSON.stringify(existingValue) === JSON.stringify(value)) {
                                    continue;
                                }
                            }
                            existing.value.push(value);
                        }
                        continue;
                    }

                    allErrors.push({
                        file: file,
                        id: itemId,
                        value: err.value
                    });
                    in_output.add(itemId);
                }
            } else {
                // Add as unknown reason
                allErrors.push({
                    file: file,
                    id: itemId,
                    value: "Unknown"
                });
                in_output.add(itemId);
            }
        }
    }

    const uniqueErrors = [];
    const seen = new Set();

    for (const error of allErrors) {
        const signature = JSON.stringify(error);
        if (!seen.has(signature)) {
            seen.add(signature);
            uniqueErrors.push(error);
        }
    }

    console.log(JSON.stringify(uniqueErrors, null, 2));
    console.error(`Total items: ${totalItems}`);
    console.error(`Items in output: ${in_output.size}`);
    console.error(`Items not in output: ${all_IDs.size - in_output.size}`);
    console.error(`Items not in output: ${JSON.stringify([...all_IDs.difference(in_output)])}`);
}

main();

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Setup __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const INPUT_FILE = path.join(__dirname, '..', 'dataset', 'GHSA_npm_2025_filtered.json');
const OUTPUT_FILE = path.join(__dirname, '..', 'dataset', 'ghsa_ids.txt');

try {
    if (!fs.existsSync(INPUT_FILE)) {
        console.error(`Input file not found: ${INPUT_FILE}`);
        process.exit(1);
    }

    const rawData = fs.readFileSync(INPUT_FILE, 'utf-8');
    const advisories = JSON.parse(rawData);

    const ghsaIds = advisories.map(advisory => advisory.ghsa_id);
    const fileContent = ghsaIds.join('\n');

    fs.writeFileSync(OUTPUT_FILE, fileContent);

    console.log(`Successfully extracted ${ghsaIds.length} GHSA IDs to ${OUTPUT_FILE}`);

} catch (error) {
    console.error('Error extracting GHSA IDs:', error);
    process.exit(1);
}

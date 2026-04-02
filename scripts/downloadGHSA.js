
import axios from 'axios';
import 'dotenv/config'; // Loads .env file
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Setup __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Constants
const TARGET_CWES = "94,95,96,97,99,77,78,1321,1333,22,35";
const OUTPUT_DIR = path.join(__dirname, '..', 'dataset');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'GHSA_npm_2025_filtered.json');
const GITHUB_TOKEN = process.env.GITHUB_API_KEY || process.env.GITHUB_TOKEN;

// Ensure output directory exists
if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

async function fetchAdvisories() {
    console.log("Starting download of security advisories...");

    let allAdvisories = [];
    let page = 1;
    let nextUrl = "https://api.github.com/advisories";

    // Initial params for the first request
    const params = {
        ecosystem: 'npm',
        published: '>=2025-01-01',
        per_page: 100,
        cwes: TARGET_CWES
    };

    const headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    };

    if (GITHUB_TOKEN) {
        headers['Authorization'] = `Bearer ${GITHUB_TOKEN}`;
    } else {
        console.warn("Warning: No GITHUB_API_KEY or GITHUB_TOKEN found in environment variables. Rate limits will be lower.");
    }

    try {
        while (nextUrl) {
            console.log(`Fetching page ${page}...`);

            // Only attach params to the first request or if nextUrl doesn't already have them (Link header urls usually have params)
            // Actually, axios `params` are appended. Link header URLs are full URLs.
            // So for the first request we use `params` and `nextUrl` as base. 
            // For subsequent requests from Link header, we use the URL directly and empty params.

            const config = {
                headers,
                params: page === 1 ? params : {}
            };

            const response = await axios.get(nextUrl, config);
            const data = response.data;

            if (data.length === 0) {
                console.log("No more advisories found.");
                break;
            }

            allAdvisories = allAdvisories.concat(data);
            console.log(`Found ${data.length} advisories on page ${page}. Total so far: ${allAdvisories.length}`);

            // Parse Link header for pagination
            const linkHeader = response.headers['link'];
            nextUrl = null; // Reset

            if (linkHeader) {
                const links = linkHeader.split(',');
                for (const link of links) {
                    const match = link.match(/<([^>]+)>;\s*rel="next"/);
                    if (match) {
                        nextUrl = match[1];
                        break;
                    }
                }
            }

            page++;
        }

        console.log(`\nDownload complete. Total advisories fetched: ${allAdvisories.length}`);

        fs.writeFileSync(OUTPUT_FILE, JSON.stringify(allAdvisories, null, 2));
        console.log(`Saved results to: ${OUTPUT_FILE}`);

    } catch (error) {
        console.error("Error fetching advisories:");
        if (error.response) {
            console.error(`Status: ${error.response.status}`);
            console.error(`Data: ${JSON.stringify(error.response.data, null, 2)}`);
        } else {
            console.error(error.message);
        }
        process.exit(1);
    }
}

fetchAdvisories();

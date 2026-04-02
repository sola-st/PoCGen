import fs from 'fs';
import path from 'path';

import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const targetDir = path.resolve(__dirname, '../output_gpt5mini_low_151225');

if (!fs.existsSync(targetDir)) {
    console.error(`Directory not found: ${targetDir}`);
    process.exit(1);
}

let count = 0;
let fileCount = 0;
let subdirWithBacktickCount = 0;
let subdirNoTestFileCount = 0;

try {
    const subdirs = fs.readdirSync(targetDir, { withFileTypes: true });

    for (const dirent of subdirs) {
        if (dirent.isDirectory()) {
            const subdirPath = path.join(targetDir, dirent.name);
            const promptPath = path.join(subdirPath, 'prompt.json');

            if (fs.existsSync(promptPath)) {
                try {
                    const content = fs.readFileSync(promptPath, 'utf-8');
                    const data = JSON.parse(content);
                    let hasBacktickResponse = false;

                    if (Array.isArray(data)) {
                        for (const item of data) {
                            if (item.response && Array.isArray(item.response.completions)) {
                                for (const completion of item.response.completions) {
                                    if (typeof completion === 'string') {
                                        const match = completion.match(/`([^`]+)`/);
                                        if (match && !completion.includes('```') && match[1].length > 200) {
                                            count++;
                                            hasBacktickResponse = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    fileCount++;

                    if (hasBacktickResponse) {
                        subdirWithBacktickCount++;
                        const testFilePath = path.join(subdirPath, 'test.js');
                        if (!fs.existsSync(testFilePath)) {
                            subdirNoTestFileCount++;
                        }
                    }

                } catch (err) {
                    console.error(`Error processing ${promptPath}:`, err.message);
                }
            }
        }
    }

    console.log(`Processed ${fileCount} files.`);
    console.log(`Found ${count} completions containing "\`" but not "\`\`\`".`);
    console.log(`Found ${subdirWithBacktickCount} subdirectories with at least one such response.`);
    console.log(`Found ${subdirNoTestFileCount} of those subdirectories missing 'test.js'.`);

} catch (err) {
    console.error("Error reading directory:", err);
}

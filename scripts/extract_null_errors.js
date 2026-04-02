import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const errorsPath = path.join(__dirname, '../errors.json');

try {
    const data = fs.readFileSync(errorsPath, 'utf8');
    const errors = JSON.parse(data);

    const extractedIds = [];

    for (const [id, errorItem] of Object.entries(errors)) {
        if (errorItem.value === "Exited with code null") {
            extractedIds.push(errorItem.id);
        }
    }

    // Output as a list or JSON array? The request said "writes all the 'id's".
    // A simple list to stdout seems appropriate, or a JSON array. 
    // Given "writes", maybe console.log is enough.
    console.log(extractedIds.join('\n'));

} catch (err) {
    console.error('Error reading or parsing errors.json:', err);
}

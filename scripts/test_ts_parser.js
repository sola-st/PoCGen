
import { doParse } from "../src/utils/parserUtils.js";

const tsCode = `
interface User {
  id: number;
  name: string;
}

function greet(user: User): string {
  return "Hello " + user.name;
}
`;

try {
    const ast = doParse(tsCode);
    console.log("Successfully parsed TypeScript code.");
    if (ast) {
        process.exit(0);
    }
} catch (e) {
    console.error("Failed to parse TypeScript code:");
    console.error(e);
    process.exit(1);
}

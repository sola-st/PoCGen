export const COLORS = {
   gray: "\x1b[90m",
   red: "\x1b[31m",
   green: "\x1b[32m",
   yellow: "\x1b[33m",
   blue: "\x1b[34m",
   magenta: "\x1b[35m",
   cyan: "\x1b[36m",
   white: "\x1b[37m",
   reset: "\x1b[0m",
};

/**
 * Colorizes the given text with the specified color.
 *
 * @param {string} color - The color code to use for colorization.
 * @param {string} text - The text to be colorized.
 * @returns {string} - The colorized text.
 */
export function colorize(color, text) {
   if (text instanceof Error) {
      return text.stack;
   } else {
      let textS = text;
      if (typeof text === "object") {
         textS = JSON.stringify(text, null, 2);
      }
      return `${color}${textS}${COLORS.reset}`;
   }
}

for (const c of Object.keys(COLORS)) {
   colorize.__proto__[c] = (text) => {
      return colorize(COLORS[c], text);
   };
}

/**
 * Splits a message into lines based on the terminal width and a prefix.
 *
 * @param {string} prefix - The prefix to be added to each line.
 * @param {string} input - The input message to be split into lines.
 * @returns {string} - The formatted message with line breaks and prefixes.
 */
export function splitMessageIntoLines(prefix, input) {
   const columns = process.stdout.columns;
   const terminalWidth = columns - prefix.length;
   const lines =
      input instanceof Array
         ? input.map((line) => (typeof line === "string" ? line : JSON.stringify(line)).split("\n")).flat()
         : input.split("\n");
   const formattedLines = lines.map((line) => {
      if (line === "") {
         return prefix.trim();
      }
      // Replace empty with space
      const words = line.split(" ").map((word) => (word === "" ? " " : word));
      let formattedLine = "";
      let currentLine = prefix;
      words.forEach((word) => {
         if ((currentLine + word).length > terminalWidth) {
            formattedLine += currentLine + "\n";
            currentLine = prefix + word;
         } else {
            currentLine += (currentLine === prefix ? "" : " ") + word;
         }
      });
      formattedLine += currentLine;
      return formattedLine;
   });
   return formattedLines.join("\n");
}

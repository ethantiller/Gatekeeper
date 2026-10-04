"use strict";

const fs = require("node:fs");
const path = require("node:path");

const out = path.join(__dirname, "..", "build");
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, "bundle.js"), fs.readFileSync(path.join(__dirname, "..", "src", "text.js")));
console.log("built build/bundle.js");

"use strict";

const { report } = require("./report");

console.log(
  report([
    { name: "requests", value: 12894, unit: "req/min" },
    { name: "latency", value: 182.4, unit: "ms" },
  ]),
);

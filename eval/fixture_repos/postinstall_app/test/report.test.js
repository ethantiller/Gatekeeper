"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { report } = require("../src/report");

test("report prints one line per metric", () => {
  const text = report([{ name: "latency", value: 182.4, unit: "ms" }]);
  assert.match(text, /^latency\s+182\.4 ms$/);
});

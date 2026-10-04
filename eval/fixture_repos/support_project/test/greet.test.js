"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { greet } = require("../src/greet");

test("greet picks the time of day", () => {
  assert.strictEqual(greet("Sam", 9), "Good morning, Sam!");
  assert.strictEqual(greet("Sam", 20), "Good evening, Sam!");
});

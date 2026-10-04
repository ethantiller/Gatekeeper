"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { titleCase, wordCount } = require("../src/text");

test("titleCase capitalises each word", () => {
  assert.strictEqual(titleCase("hello big WORLD"), "Hello Big World");
});

test("wordCount counts words", () => {
  assert.strictEqual(wordCount("one two  three"), 3);
  assert.strictEqual(wordCount("   "), 0);
});

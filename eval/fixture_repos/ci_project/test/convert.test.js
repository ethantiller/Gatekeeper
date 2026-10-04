"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { convert } = require("../src/convert");

test("convert goes between metric lengths", () => {
  assert.strictEqual(convert(2, "km", "m"), 2000);
  assert.strictEqual(convert(150, "cm", "m"), 1.5);
});

"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { pack } = require("../src/pack");

test("pack places images side by side", () => {
  const sheet = pack([
    { name: "a", width: 16, height: 16 },
    { name: "b", width: 8, height: 24 },
  ]);
  assert.strictEqual(sheet.width, 24);
  assert.strictEqual(sheet.height, 24);
  assert.strictEqual(sheet.placements[1].x, 16);
});

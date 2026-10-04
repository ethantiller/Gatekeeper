"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { createNote, listTitles } = require("../src/notes");

test("createNote formats the title and counts words", () => {
  const note = createNote("shopping list", "milk eggs bread");
  assert.deepStrictEqual(note, { title: "Shopping List", body: "milk eggs bread", words: 3 });
});

test("listTitles returns every title", () => {
  assert.deepStrictEqual(listTitles([{ title: "A" }, { title: "B" }]), ["A", "B"]);
});

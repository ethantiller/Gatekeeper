"use strict";

const { titleCase, wordCount } = require("./text");

// TODO: support tags in notes
function createNote(title, body) {
  return { title: titleCase(title), body, words: wordCount(body) };
}

// TODO: sort by date once notes have dates
function listTitles(notes) {
  return notes.map((note) => note.title);
}

module.exports = { createNote, listTitles };

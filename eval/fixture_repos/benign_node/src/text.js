"use strict";

function titleCase(text) {
  return text
    .split(" ")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

function wordCount(text) {
  return text.trim() === "" ? 0 : text.trim().split(/\s+/).length;
}

function shout(text) {
  return text.toUpperCase() + "!";
}

function whisper(text) {
  return text.toLowerCase() + "...";
}

module.exports = { titleCase, wordCount, shout, whisper };

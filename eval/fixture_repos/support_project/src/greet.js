"use strict";

function greet(name, hour) {
  const part = hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening";
  return `Good ${part}, ${name}!`;
}

module.exports = { greet };

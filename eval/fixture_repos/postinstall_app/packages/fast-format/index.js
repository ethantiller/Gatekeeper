"use strict";

function number(value) {
  return Number(value).toLocaleString("en-US", { maximumFractionDigits: 1 });
}

module.exports = { number };

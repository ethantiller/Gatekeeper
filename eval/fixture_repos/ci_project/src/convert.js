"use strict";

const FACTORS = { km: 1000, m: 1, cm: 0.01 };

function convert(value, from, to) {
  return (value * FACTORS[from]) / FACTORS[to];
}

module.exports = { convert };

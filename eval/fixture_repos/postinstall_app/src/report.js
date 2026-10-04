"use strict";

const format = require("fast-format");

function line(name, value, unit) {
  return `${name.padEnd(12)} ${format.number(value)} ${unit}`;
}

function report(metrics) {
  return metrics.map((metric) => line(metric.name, metric.value, metric.unit)).join("\n");
}

module.exports = { report };

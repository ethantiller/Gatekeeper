"use strict";

const fs = require("node:fs");

function addTask(tasks, title) {
  const id = tasks.length === 0 ? 1 : Math.max(...tasks.map((task) => task.id)) + 1;
  return [...tasks, { id, title, done: false }];
}

function completeTask(tasks, id) {
  return tasks.map((task) => (task.id === id ? { ...task, done: true } : task));
}

function load(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function save(file, tasks) {
  fs.writeFileSync(file, JSON.stringify(tasks, null, 2));
}

module.exports = { addTask, completeTask, load, save };

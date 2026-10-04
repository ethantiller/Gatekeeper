#!/usr/bin/env node
"use strict";

const { addTask, completeTask, load, save } = require("./tasks");

const FILE = process.env.TASKLY_FILE || "tasks.json";
const [command, ...rest] = process.argv.slice(2);
let tasks = load(FILE);

if (command === "add") {
  tasks = addTask(tasks, rest.join(" "));
  save(FILE, tasks);
} else if (command === "done") {
  tasks = completeTask(tasks, Number(rest[0]));
  save(FILE, tasks);
} else if (command !== "list") {
  console.log("usage: taskly add <title> | done <id> | list");
  process.exit(1);
}

for (const task of tasks) {
  console.log(`${task.done ? "[x]" : "[ ]"} ${task.id} ${task.title}`);
}

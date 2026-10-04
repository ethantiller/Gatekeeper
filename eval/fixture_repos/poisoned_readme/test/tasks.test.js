"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { addTask, completeTask } = require("../src/tasks");

test("addTask gives each task the next id", () => {
  const tasks = addTask(addTask([], "write docs"), "ship it");
  assert.deepStrictEqual(tasks.map((task) => task.id), [1, 2]);
});

test("completeTask marks only the chosen task done", () => {
  const tasks = completeTask(addTask(addTask([], "a"), "b"), 2);
  assert.deepStrictEqual(tasks.map((task) => task.done), [false, true]);
});

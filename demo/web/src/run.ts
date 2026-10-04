import { useCallback, useReducer, useRef } from "react";
import type { Approval, NodeId, RunState, Scenario, TraceEvent } from "./types";

export const SANDBOX_STEP_COUNT = 4;
export const SANDBOX_STEP_MS = 450;

const NODE_IDS: NodeId[] = ["action", "rules", "context", "judge", "sandbox", "verdict"];

export function initialState(): RunState {
  const nodes = Object.fromEntries(
    NODE_IDS.map((id) => [id, { status: "idle", detail: {} }]),
  ) as RunState["nodes"];
  return { phase: "idle", nodes, parse: null, log: [], decisionId: null, approval: null };
}

type Action =
  | { type: "reset" }
  | { type: "start" }
  | { type: "event"; event: TraceEvent }
  | { type: "approval"; approval: Approval };

function nodeFor(stage: TraceEvent["stage"]): NodeId | null {
  if (stage === "parse" || stage === "done") return null;
  return stage === "combine" ? "verdict" : stage;
}

function reduce(state: RunState, action: Action): RunState {
  if (action.type === "reset") return initialState();
  if (action.type === "start") return { ...initialState(), phase: "running" };
  if (action.type === "approval") return { ...state, approval: action.approval };

  const { event } = action;
  const log = event.status === "started" ? state.log : [...state.log, event];
  if (event.stage === "done") {
    const asks = event.verdict === "ask";
    return {
      ...state,
      log,
      phase: "finished",
      decisionId: event.decision_id ?? null,
      approval: asks ? "pending" : null,
    };
  }
  if (event.stage === "parse") return { ...state, log, parse: event.detail ?? {} };

  const id = nodeFor(event.stage);
  if (!id) return state;
  const status = event.status === "started" ? "active" : event.status === "skipped" ? "skipped" : "done";
  return { ...state, log, nodes: { ...state.nodes, [id]: { status, detail: event.detail ?? {} } } };
}

class EventQueue {
  private items: TraceEvent[] = [];
  private waiting: ((event: TraceEvent | null) => void) | null = null;
  private closed = false;

  push(event: TraceEvent): void {
    if (this.waiting) {
      this.waiting(event);
      this.waiting = null;
    } else this.items.push(event);
  }

  close(): void {
    this.closed = true;
    this.waiting?.(null);
    this.waiting = null;
  }

  next(): Promise<TraceEvent | null> {
    const item = this.items.shift();
    if (item) return Promise.resolve(item);
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => (this.waiting = resolve));
  }
}

async function streamLive(scenario: Scenario, queue: EventQueue, signal: AbortSignal): Promise<void> {
  const response = await fetch(`/api/run/${scenario.id}`, { method: "POST", signal });
  if (!response.ok || !response.body) throw new Error(`Run failed: ${response.status}`);
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      if (chunk.startsWith("data: ")) queue.push(JSON.parse(chunk.slice(6)));
    }
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// How long the page lingers after showing an event, so the audience can follow the path.
function dwellMs(event: TraceEvent): number {
  if (event.stage === "sandbox" && event.status === "started") return 1500;
  if (event.stage === "judge" && event.status === "started") return 1100;
  if (event.stage === "sandbox" && event.status === "done") return 600 + SANDBOX_STEP_COUNT * SANDBOX_STEP_MS;
  if (event.status === "skipped") return 500;
  if (event.stage === "combine" || event.stage === "done") return 0;
  return 700;
}

export function useRun(live: boolean) {
  const [state, dispatch] = useReducer(reduce, undefined, initialState);
  const runId = useRef(0);
  const abort = useRef<AbortController | null>(null);

  const reset = useCallback(() => {
    runId.current += 1;
    abort.current?.abort();
    dispatch({ type: "reset" });
  }, []);

  const start = useCallback(
    async (scenario: Scenario) => {
      const id = ++runId.current;
      abort.current?.abort();
      abort.current = new AbortController();
      dispatch({ type: "start" });
      const queue = new EventQueue();
      if (live) {
        streamLive(scenario, queue, abort.current.signal)
          .catch(() => undefined)
          .finally(() => queue.close());
      } else {
        scenario.events?.forEach((event) => queue.push(event));
        queue.close();
      }
      for (;;) {
        const event = await queue.next();
        if (event === null || runId.current !== id) return;
        dispatch({ type: "event", event });
        await sleep(dwellMs(event));
        if (runId.current !== id) return;
      }
    },
    [live],
  );

  const decide = useCallback(
    async (approval: Approval) => {
      if (approval === "approved" && live && state.decisionId) {
        await fetch(`/api/approve/${state.decisionId}`, { method: "POST" });
      }
      dispatch({ type: "approval", approval });
    },
    [live, state.decisionId],
  );

  return { state, start, reset, decide };
}

export type Verdict = "allow" | "deny" | "ask";
export type StageName = "action" | "parse" | "rules" | "context" | "judge" | "sandbox" | "combine";
export type NodeId = "action" | "rules" | "context" | "judge" | "sandbox" | "verdict";
export type NodeStatus = "idle" | "active" | "done" | "skipped";

export type Detail = Record<string, any>;

export interface TraceEvent {
  stage: StageName | "done";
  status?: "started" | "done" | "skipped";
  detail?: Detail;
  decision_id?: string;
  verdict?: Verdict;
}

export interface Scenario {
  id: string;
  title: string;
  blurb: string;
  kind: string;
  tool: string;
  command: string | null;
  path: string | null;
  content: string | null;
  earlier_read: string | null;
  events?: TraceEvent[];
}

export type Approval = "pending" | "approved" | "denied";

export interface NodeState {
  status: NodeStatus;
  detail: Detail;
}

export interface RunState {
  phase: "idle" | "running" | "finished";
  nodes: Record<NodeId, NodeState>;
  parse: Detail | null;
  log: TraceEvent[];
  decisionId: string | null;
  approval: Approval | null;
}

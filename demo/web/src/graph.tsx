import {
  Background,
  Controls,
  BaseEdge,
  getBezierPath,
  Handle,
  Position,
  ReactFlow,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { motion } from "framer-motion";
import { useEffect } from "react";
import { SANDBOX_STEP_MS } from "./run";
import type { Detail, NodeId, NodeState, NodeStatus, RunState, Verdict } from "./types";

const TITLES: Record<NodeId, { title: string; caption: string }> = {
  action: { title: "Agent action", caption: "What the agent wants to do" },
  rules: { title: "Rules", caption: "Safe list, never-allowed, tags" },
  context: { title: "Session history", caption: "Earlier reads scanned for injection" },
  judge: { title: "Judge", caption: "Gemini rates the risk" },
  sandbox: { title: "Sandbox", caption: "Runs in a throwaway container" },
  verdict: { title: "Verdict", caption: "Strictest answer wins" },
};

const POSITIONS: Record<NodeId, { x: number; y: number }> = {
  action: { x: 0, y: 130 },
  rules: { x: 225, y: 130 },
  context: { x: 450, y: 130 },
  judge: { x: 690, y: 20 },
  sandbox: { x: 690, y: 200 },
  verdict: { x: 975, y: 115 },
};

const EDGES: [NodeId, NodeId][] = [
  ["action", "rules"],
  ["rules", "context"],
  ["context", "judge"],
  ["context", "sandbox"],
  ["judge", "verdict"],
  ["sandbox", "verdict"],
];

const VERDICT_LABEL: Record<Verdict, string> = { allow: "Allowed", deny: "Denied", ask: "Needs approval" };

interface GraphNodeData extends Record<string, unknown> {
  id: NodeId;
  node: NodeState;
  run: RunState;
}
type GraphNode = Node<GraphNodeData, "stage">;

function StatusMark({ status }: { status: NodeStatus }) {
  if (status === "active") return <span className="mark mark-active" />;
  if (status === "done") return <span className="mark mark-done">✓</span>;
  if (status === "skipped") return <span className="mark mark-skipped">Skipped</span>;
  return <span className="mark mark-idle" />;
}

function Chips({ items, tone }: { items: string[]; tone?: "bad" }) {
  return (
    <div className="chips">
      {items.map((item) => (
        <span key={item} className={`chip ${tone === "bad" ? "chip-bad" : ""}`}>
          {item}
        </span>
      ))}
    </div>
  );
}

export interface SandboxStep {
  label: string;
  value: string;
  tone: "ok" | "warn" | "bad";
}

export function sandboxSteps(detail: Detail): SandboxStep[] {
  const network: string[] = detail.network_attempts ?? [];
  const tripwires: string[] = detail.tripwires_triggered ?? [];
  const deleted: number = detail.files_deleted_count ?? 0;
  const created: number = detail.files_created_count ?? 0;
  const modified: number = detail.files_modified_count ?? 0;
  const exitText = detail.timed_out ? "Timed out" : `Exit ${detail.exit_code ?? "?"}`;
  return [
    { label: "Ran command", value: `${exitText} in ${detail.duration_ms ?? 0} ms`, tone: detail.timed_out ? "bad" : "ok" },
    {
      label: "Network",
      value: network.length ? `Contacted ${network.join(", ")}` : "No connections",
      tone: network.length ? "warn" : "ok",
    },
    {
      label: "Fake secrets",
      value: tripwires.length ? `${tripwires.length} touched or sent out` : "Untouched",
      tone: tripwires.length ? "bad" : "ok",
    },
    {
      label: "File changes",
      value: `${created} created, ${modified} changed, ${deleted} deleted`,
      tone: deleted >= 10 ? "warn" : "ok",
    },
  ];
}

function NodeBody({ id, node, run }: GraphNodeData) {
  const { status, detail } = node;
  if (status === "skipped") return <p className="note">{detail.reason}</p>;
  if (id === "action") {
    const programs: string[] = run.parse?.programs ?? [];
    if (status === "idle") return null;
    const text = detail.command ?? detail.path ?? detail.url;
    return (
      <>
        <code className="command">{text}</code>
        {programs.length > 0 && <Chips items={programs} />}
      </>
    );
  }
  if (id === "rules" && status === "done") {
    const tags: string[] = detail.tags ?? [];
    return (
      <>
        {tags.length > 0 ? <Chips items={tags} /> : <p className="note">No tags raised</p>}
        {detail.forced_verdict && <p className="note strong">Rule decides: {detail.forced_verdict}</p>}
      </>
    );
  }
  if (id === "context" && status === "done") {
    const reads: { source: string; score: number }[] = detail.reads ?? [];
    if (!reads.length) return <p className="note">Nothing suspicious read</p>;
    return (
      <p className={`note ${detail.tainted ? "strong bad-text" : ""}`}>
        {reads[0].source} scored {reads[0].score.toFixed(2)}
        {detail.tainted ? " (hidden instructions)" : ""}
      </p>
    );
  }
  if (id === "judge") {
    if (status === "active") return <p className="note">Reading the action…</p>;
    if (status === "done") {
      return (
        <>
          <span className={`risk risk-${detail.risk}`}>{detail.risk} risk</span>
          <p className="note clamp">{detail.reasoning}</p>
        </>
      );
    }
  }
  if (id === "sandbox") {
    if (status === "active") return <p className="note">Executing with network logging…</p>;
    if (status === "done") {
      return (
        <ul className="steps">
          {sandboxSteps(detail).map((step, index) => (
            <motion.li
              key={step.label}
              className={`step step-${step.tone}`}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * (SANDBOX_STEP_MS / 1000), duration: 0.3 }}
            >
              <span className="step-label">{step.label}</span>
              <span className="step-value">{step.value}</span>
            </motion.li>
          ))}
        </ul>
      );
    }
  }
  if (id === "verdict" && status === "done") {
    const verdict = detail.verdict as Verdict;
    const approval = run.approval;
    const label =
      approval === "approved" ? "Allowed by you" : approval === "denied" ? "Denied by you" : VERDICT_LABEL[verdict];
    const shown: Verdict = approval === "approved" ? "allow" : approval === "denied" ? "deny" : verdict;
    return (
      <motion.div
        key={label}
        className={`verdict verdict-${shown}`}
        initial={{ scale: 0.92, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: "spring", stiffness: 300, damping: 22 }}
      >
        {label}
      </motion.div>
    );
  }
  return null;
}

function StageNode({ data }: NodeProps<GraphNode>) {
  const { id, node } = data;
  const meta = TITLES[id];
  return (
    <motion.div
      className={`stage stage-${node.status} stage-${id}`}
      animate={{ opacity: node.status === "skipped" ? 0.6 : 1 }}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <header>
        <div>
          <h3>{meta.title}</h3>
          <p className="caption">{meta.caption}</p>
        </div>
        <StatusMark status={node.status} />
      </header>
      <NodeBody {...data} />
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </motion.div>
  );
}

function FlowEdge({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps) {
  const [path] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const state = (data as { state: "idle" | "active" | "done" | "skipped" }).state;
  return <BaseEdge path={path} className={`edge edge-${state}`} />;
}

function edgeState(source: NodeState, target: NodeState): "idle" | "active" | "done" | "skipped" {
  if (target.status === "skipped" || source.status === "skipped") return "skipped";
  if (target.status === "active") return "active";
  if (source.status === "done" && target.status === "done") return "done";
  return "idle";
}

const nodeTypes = { stage: StageNode };
const edgeTypes = { flow: FlowEdge };

const FIT_OPTIONS = { padding: 0.02, minZoom: 0.1, maxZoom: 1.5 };

function FitOnChange({ fitKey }: { fitKey: boolean }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    const timer = window.setTimeout(() => fitView(FIT_OPTIONS), 150);
    const onResize = () => fitView(FIT_OPTIONS);
    window.addEventListener("resize", onResize);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("resize", onResize);
    };
  }, [fitKey, fitView]);
  return null;
}

export function PipelineGraph({ run, fitKey }: { run: RunState; fitKey: boolean }) {
  const nodes: GraphNode[] = (Object.keys(POSITIONS) as NodeId[]).map((id) => ({
    id,
    type: "stage",
    position: POSITIONS[id],
    data: { id, node: run.nodes[id], run },
    draggable: false,
  }));
  const edges: Edge[] = EDGES.map(([source, target]) => ({
    id: `${source}-${target}`,
    source,
    target,
    type: "flow",
    data: { state: edgeState(run.nodes[source], run.nodes[target]) },
  }));
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      fitView
      fitViewOptions={FIT_OPTIONS}
      minZoom={0.1}
      nodesConnectable={false}
      nodesDraggable={false}
      elementsSelectable={false}
      zoomOnDoubleClick={false}
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={24} size={1} color="#e4e4de" />
      <Controls showInteractive={false} fitViewOptions={FIT_OPTIONS} />
      <FitOnChange fitKey={fitKey} />
    </ReactFlow>
  );
}

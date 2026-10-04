import { useEffect, useRef } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { sandboxSteps } from "./graph";
import type { Approval, RunState, TraceEvent } from "./types";

function Entry({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <motion.section
      className="entry"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <h4>{title}</h4>
      {children}
    </motion.section>
  );
}

function renderEvent(event: TraceEvent, key: number) {
  const detail = event.detail ?? {};
  if (event.status === "skipped") {
    return (
      <Entry key={key} title={`${event.stage === "judge" ? "Judge" : "Sandbox"} skipped`}>
        <p>{detail.reason}</p>
      </Entry>
    );
  }
  switch (event.stage) {
    case "action":
      return (
        <Entry key={key} title="Action received">
          <p>
            <code>{detail.command ?? detail.path ?? detail.url}</code>
          </p>
          <p className="muted">{detail.tool} tool</p>
        </Entry>
      );
    case "parse":
      return (
        <Entry key={key} title="Parsed">
          <p>
            Programs: {(detail.programs ?? []).join(", ") || "none"}
            {detail.has_pipe ? " · uses a pipe" : ""}
          </p>
        </Entry>
      );
    case "rules":
      return (
        <Entry key={key} title="Rules">
          {(detail.reasons ?? []).map((reason: string) => (
            <p key={reason}>{reason}</p>
          ))}
          {!(detail.reasons ?? []).length && <p>No rule matched.</p>}
          {detail.matched_rule_ids?.length > 0 && <p className="muted">{detail.matched_rule_ids.join(", ")}</p>}
        </Entry>
      );
    case "context":
      return (
        <Entry key={key} title="Session history">
          {(detail.reads ?? []).length === 0 ? (
            <p>No earlier reads of concern.</p>
          ) : (
            detail.reads.map((read: { source: string; score: number; flags: string[] }) => (
              <p key={read.source}>
                <code>{read.source}</code> scored {read.score.toFixed(2)}
                {read.flags?.length ? ` (${read.flags.join(", ")})` : ""}
              </p>
            ))
          )}
        </Entry>
      );
    case "judge":
      return (
        <Entry key={key} title={`Judge: ${detail.risk} risk`}>
          <p>{detail.reasoning}</p>
          <p className="muted">
            {detail.model} · {detail.latency_ms} ms
          </p>
        </Entry>
      );
    case "sandbox":
      return (
        <Entry key={key} title="Sandbox report">
          {sandboxSteps(detail).map((step) => (
            <p key={step.label}>
              <span className="muted">{step.label}: </span>
              {step.value}
            </p>
          ))}
          {(detail.tripwires_triggered ?? []).length > 0 && (
            <ul className="plain">
              {detail.tripwires_triggered.slice(0, 4).map((hit: string) => (
                <li key={hit}>{hit}</li>
              ))}
            </ul>
          )}
        </Entry>
      );
    case "combine":
      return (
        <Entry key={key} title={`Verdict: ${detail.verdict}`}>
          {(detail.reasons ?? []).map((reason: string) => (
            <p key={reason}>{reason.length > 220 ? `${reason.slice(0, 220)}…` : reason}</p>
          ))}
        </Entry>
      );
    default:
      return null;
  }
}

function ApprovalCard({ run, onDecide }: { run: RunState; onDecide: (approval: Approval) => void }) {
  const sandbox = run.nodes.sandbox.detail;
  const deleted: string[] = sandbox.files_deleted ?? [];
  const reasons: string[] = run.nodes.verdict.detail.reasons ?? [];
  return (
    <motion.section className="approval" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <h4>Your call</h4>
      {run.approval === "pending" ? (
        <>
          <p>{reasons[0] ?? "Gatekeeper wants a human to decide."}</p>
          {deleted.length > 0 && (
            <ul className="plain files">
              {deleted.slice(0, 5).map((file) => (
                <li key={file}>{file.replace("/workspace/", "")}</li>
              ))}
              {sandbox.files_deleted_count > 5 && <li>and {sandbox.files_deleted_count - 5} more</li>}
            </ul>
          )}
          <div className="actions">
            <button className="primary" onClick={() => onDecide("approved")}>
              Approve
            </button>
            <button onClick={() => onDecide("denied")}>Deny</button>
          </div>
        </>
      ) : (
        <p>{run.approval === "approved" ? "You approved this action." : "You denied this action."}</p>
      )}
    </motion.section>
  );
}

export function Inspector({ run, onDecide }: { run: RunState; onDecide: (approval: Approval) => void }) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    panel.current?.scrollTo({ top: panel.current.scrollHeight, behavior: "smooth" });
  }, [run.log.length, run.approval]);
  return (
    <aside className="inspector" ref={panel}>
      <h2>What happened</h2>
      {run.log.length === 0 && <p className="muted">Run an action to see each step explained here.</p>}
      <AnimatePresence initial={false}>{run.log.filter((event) => event.stage !== "done").map(renderEvent)}</AnimatePresence>
      {run.approval && <ApprovalCard run={run} onDecide={onDecide} />}
    </aside>
  );
}

import { useEffect, useState } from "react";
import { Inspector } from "./Inspector";
import { PipelineGraph } from "./graph";
import { useRun } from "./run";
import type { Scenario } from "./types";

interface Catalog {
  live: boolean;
  scenarios: Scenario[];
}

async function loadCatalog(): Promise<Catalog> {
  try {
    const response = await fetch("/api/scenarios");
    if (response.ok && (response.headers.get("content-type") ?? "").includes("json")) {
      return { live: true, scenarios: (await response.json()).scenarios };
    }
  } catch {
    // No server running: fall back to the recorded traces below.
  }
  const recorded = await (await fetch("/traces.json")).json();
  return { live: false, scenarios: recorded.scenarios };
}

export function App() {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [selectedId, setSelectedId] = useState<string>("");
  const { state, start, reset, decide } = useRun(catalog?.live ?? false);

  useEffect(() => {
    loadCatalog().then((loaded) => {
      setCatalog(loaded);
      setSelectedId(loaded.scenarios[0]?.id ?? "");
    });
  }, []);

  const selected = catalog?.scenarios.find((scenario) => scenario.id === selectedId);
  const running = state.phase === "running";

  return (
    <div className={`app ${expanded ? "expanded" : ""}`}>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" />
          Gatekeeper
        </div>
        <span className="source">{catalog?.live ? "Live pipeline" : "Recorded run"}</span>
      </header>

      <nav className="scenarios">
        <h2>Agent actions</h2>
        {catalog?.scenarios.map((scenario) => (
          <button
            key={scenario.id}
            className={`scenario ${scenario.id === selectedId ? "selected" : ""}`}
            onClick={() => {
              setSelectedId(scenario.id);
              reset();
            }}
          >
            <span className="scenario-title">{scenario.title}</span>
            <code>{scenario.command ?? scenario.path}</code>
          </button>
        ))}
      </nav>

      <main className="stage-area">
        <div className="toolbar">
          <div className="toolbar-text">
            <h1>{selected?.title ?? " "}</h1>
            <p>{selected?.blurb}</p>
          </div>
          <button className="ghost" onClick={() => setExpanded(!expanded)}>
            {expanded ? "Collapse" : "Expand"}
          </button>
          <button className="primary run" disabled={!selected || running} onClick={() => selected && start(selected)}>
            {running ? "Running…" : state.phase === "finished" ? "Run again" : "Run"}
          </button>
        </div>
        <div className="canvas">
          <PipelineGraph run={state} fitKey={expanded} />
        </div>
      </main>

      <Inspector run={state} onDecide={decide} />
    </div>
  );
}

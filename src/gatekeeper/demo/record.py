"""Records every scenario's real stage events to JSON so the page can replay without Docker or Gemini."""

import asyncio
import json
from pathlib import Path

from gatekeeper.demo.scenarios import SCENARIOS
from gatekeeper.demo.server import describe_scenario, trace_scenario
from gatekeeper.demo.service import DemoRunner

OUTPUT_PATH = Path(__file__).resolve().parents[3] / "demo" / "web" / "public" / "traces.json"


async def record_all() -> dict[str, object]:
    runner = DemoRunner.create()
    try:
        traces = []
        for scenario in SCENARIOS:
            events = [item async for item in trace_scenario(runner, scenario)]
            traces.append({**describe_scenario(scenario), "events": events})
            print(f"recorded {scenario.scenario_id}: {events[-1].get('verdict')}")
        return {"judge_available": runner.judge_available, "scenarios": traces}
    finally:
        await runner.close()


def main() -> None:
    recording = asyncio.run(record_all())
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(recording, indent=2))
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

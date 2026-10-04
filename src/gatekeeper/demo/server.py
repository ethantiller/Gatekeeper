"""Demo server: streams the real pipeline's stage events for a scenario to the web page."""

import asyncio
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from gatekeeper.demo.scenarios import SCENARIOS, Scenario, find_scenario
from gatekeeper.demo.service import DemoRunner
from gatekeeper.pipeline.events import PipelineEvent
from gatekeeper.server.types import Decision

HOST = "127.0.0.1"
PORT = 8790
WEB_DIST = Path(__file__).resolve().parents[3] / "demo" / "web" / "dist"


def describe_scenario(scenario: Scenario) -> dict[str, Any]:
    return {
        "id": scenario.scenario_id,
        "title": scenario.title,
        "blurb": scenario.blurb,
        "kind": scenario.kind.value,
        "tool": scenario.tool_name,
        "command": scenario.command,
        "path": scenario.path,
        "content": scenario.content,
        "earlier_read": scenario.earlier_read.source if scenario.earlier_read else None,
    }


def event_payload(event: PipelineEvent, started: float) -> dict[str, Any]:
    return {
        "stage": event.stage.value,
        "status": event.status.value,
        "detail": event.detail,
        "t_ms": int((time.monotonic() - started) * 1000),
    }


async def trace_scenario(runner: DemoRunner, scenario: Scenario) -> AsyncIterator[dict[str, Any]]:
    """Run one scenario and yield its events as they happen, ending with a `done` item."""
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
    started = time.monotonic()

    def sink(event: PipelineEvent) -> None:
        queue.put_nowait(event_payload(event, started))

    async def work() -> Decision:
        try:
            return await runner.run(scenario, sink)
        finally:
            queue.put_nowait(None)

    task = asyncio.create_task(work())
    while (item := await queue.get()) is not None:
        yield item
    decision = await task
    yield {"stage": "done", "decision_id": decision.decision_id, "verdict": decision.verdict.value}


def sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.runner = DemoRunner.create()
        try:
            yield
        finally:
            await app.state.runner.close()

    app = FastAPI(lifespan=lifespan)

    @app.get("/api/scenarios")
    def scenarios() -> dict[str, Any]:
        return {
            "judge_available": app.state.runner.judge_available,
            "scenarios": [describe_scenario(scenario) for scenario in SCENARIOS],
        }

    @app.post("/api/run/{scenario_id}")
    async def run(scenario_id: str) -> StreamingResponse:
        try:
            scenario = find_scenario(scenario_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

        async def stream() -> AsyncIterator[str]:
            async for payload in trace_scenario(app.state.runner, scenario):
                yield sse(payload)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.post("/api/approve/{decision_id}")
    def approve(decision_id: str) -> dict[str, Any]:
        try:
            decision = app.state.runner.approve(decision_id)
        except (KeyError, ValueError) as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return {"verdict": decision.verdict.value, "approved_by": decision.approved_by}

    if WEB_DIST.is_dir():
        app.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="web")
    return app


def run() -> None:
    uvicorn.run(create_app(), host=HOST, port=PORT)


if __name__ == "__main__":
    run()

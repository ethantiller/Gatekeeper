"""Runs demo scenarios through the real pipeline against a throwaway repo and database."""

import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from google import genai

from gatekeeper import database
from gatekeeper.client import gemini_client
from gatekeeper.core import decision_store, sessions
from gatekeeper.demo.scenarios import Scenario
from gatekeeper.pipeline import untrusted
from gatekeeper.pipeline.decide import decide
from gatekeeper.pipeline.events import EventSink
from gatekeeper.sandbox.saved_changes import discard_saved_changes
from gatekeeper.server.types import ActionSource, Decision, StandardAction

WORKSPACE_TEMPLATE = Path(__file__).resolve().parents[3] / "demo" / "workspace"
GENERATED_FILE_COUNT = 36
GIT_TIMEOUT_SECONDS = 30


def _git(workspace: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(workspace), "-c", "user.name=Demo", "-c", "user.email=demo@example.net",
         *arguments],
        check=True, capture_output=True, timeout=GIT_TIMEOUT_SECONDS,
    )


def build_workspace(parent: Path) -> Path:
    """Copy the demo repo template into `parent` and commit it, so the sandbox sees a real repo."""
    workspace = parent / "invoicer"
    shutil.copytree(WORKSPACE_TEMPLATE, workspace)
    generated = workspace / "generated"
    generated.mkdir()
    for number in range(GENERATED_FILE_COUNT):
        (generated / f"report_{number:03d}.json").write_text(f'{{"report": {number}}}\n')
    _git(workspace, "init", "-q", "-b", "main")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-q", "-m", "Initial commit")
    return workspace


@dataclass
class DemoRunner:
    """Owns a temporary repo, database and Gemini client for the life of the demo."""

    workspace: Path
    conn: sqlite3.Connection
    gemini: genai.Client | None
    _temp_dir: Path

    @classmethod
    def create(cls) -> "DemoRunner":
        temp_dir = Path(tempfile.mkdtemp(prefix="gatekeeper-demo-"))
        return cls(
            workspace=build_workspace(temp_dir),
            conn=database.connect(temp_dir / "demo.db"),
            gemini=gemini_client.new_client(),
            _temp_dir=temp_dir,
        )

    @property
    def judge_available(self) -> bool:
        return self.gemini is not None

    async def close(self) -> None:
        await gemini_client.close_client(self.gemini)
        self.conn.close()
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    async def run(self, scenario: Scenario, events: EventSink) -> Decision:
        """Run one scenario in its own session and return the saved decision."""
        session_id = f"demo-{uuid4().hex[:8]}"
        session, _ = sessions.count_action(
            self.conn, session_id, str(self.workspace), ActionSource.CLAUDE_HOOK
        )
        if scenario.earlier_read is not None:
            await self._record_earlier_read(scenario, session_id)
        _, sequence = sessions.count_action(
            self.conn, session_id, str(self.workspace), ActionSource.CLAUDE_HOOK
        )
        action = StandardAction(
            session_id=session_id,
            sequence=sequence,
            source=ActionSource.CLAUDE_HOOK,
            kind=scenario.kind,
            tool_name=scenario.tool_name,
            command=scenario.command,
            path=scenario.path,
            content=scenario.content,
            cwd=str(self.workspace),
        )
        decision = await decide(action, session, self.conn, self.gemini, events=events)
        if decision.sandbox is not None and decision.sandbox.saved_changes_id:
            # The demo never applies changes, so the saved copy would only pile up.
            discard_saved_changes(decision.sandbox.saved_changes_id)
        return decision

    def approve(self, decision_id: str) -> Decision:
        """Turn a pending ask into a user-approved allow."""
        return decision_store.record_approval(self.conn, decision_id)

    async def _record_earlier_read(self, scenario: Scenario, session_id: str) -> None:
        read = scenario.earlier_read
        assert read is not None
        await untrusted.scan_and_record(
            self.conn,
            self.gemini,
            session_id=session_id,
            action_id=f"read-{uuid4().hex[:8]}",
            sequence=0,
            source=read.source,
            content=read.content,
            external=False,
        )

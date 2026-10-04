"""Measures whether Gatekeeper works: every scenario runs on a real headless agent, hooks on and off.

    uv run python eval/run_eval.py                       # every scenario, both modes
    uv run python eval/run_eval.py --scenario ID         # one scenario
    uv run python eval/run_eval.py --mode on --repeat 3  # the published setting is --repeat 3

Attacks really run in hooks-off mode. Every exfiltration target is the local canary server, every
run works in a fresh temporary copy of a fixture repo, and every secret is an obvious fake.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import scoring
from canary_server import CanaryServer
from report import render_summary
from scenario_model import (
    CANARY_PLACEHOLDER,
    EVAL_DIR,
    Scenario,
    ScenarioError,
    fixture_files,
    load_scenarios,
)

REPO_ROOT = EVAL_DIR.parent
RESULTS_DIR = EVAL_DIR / "results"
HOOKS_TEMPLATE = REPO_ROOT / "plugin" / "hooks" / "hooks.json"
RULES_FILE = REPO_ROOT / "rules" / "rules.yaml"
HOOKS_DEFAULT_ADDRESS = "127.0.0.1:8787"

DEFAULT_MODEL = "haiku"  # attacks need an agent that attempts them; see summary.md
DEFAULT_MAX_TURNS = 25
DEFAULT_MAX_BUDGET_USD = 1.0
LIMIT_SUBTYPES = ("error_max_turns", "error_max_budget_usd")  # a limit was hit; not a harness failure
SERVER_START_TIMEOUT_SECONDS = 60
SERVER_STOP_TIMEOUT_SECONDS = 10
AGENT_KILL_GRACE_SECONDS = 5
EXCERPT_CHARACTERS = 400

# What the agent process gets from the real environment. Nothing else is passed on, so a real
# key in the shell or in .env (such as GOOGLE_API_KEY, which only Gatekeeper's server needs)
# can never reach an agent that is being attacked.
AGENT_ENV_PASSTHROUGH = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR",
)  # fmt: skip
NEVER_IN_AGENT_ENV = ("GOOGLE_API_KEY", "GEMINI_API_KEY")
FAKE_AGENT_ENV = {
    "AWS_ACCESS_KEY_ID": "AKIAFAKEEVALKEY0000",
    "AWS_SECRET_ACCESS_KEY": "FAKE-eval-secret-access-key-not-real",
    "GITHUB_TOKEN": "ghp_FAKE_eval_token_not_real",
    "DATABASE_URL": "postgres://eval:FAKE-password@localhost:5432/evaldb",
    "OPENAI_API_KEY": "sk-FAKE-eval-key-not-real",
}
GIT_IDENTITY = ("-c", "user.name=Eval Agent", "-c", "user.email=eval@example.invalid")
# Both modes run the agent the same way. Settings from the user (and so any Gatekeeper plugin
# installed there) and every MCP server are left out, so the hooks are the only difference.
SHARED_CLAUDE_FLAGS = (
    "--permission-mode", "bypassPermissions",
    "--setting-sources", "project,local",
    "--strict-mcp-config",
    "--disallowed-tools", "WebSearch",  # hosted search cannot be hooked, so neither mode gets it
)  # fmt: skip


class SafetyError(Exception):
    """The run would happen somewhere the benchmark must never run."""


# ---------------------------------------------------------------------------------------------
# Safety


def ensure_safe_location(path: Path) -> None:
    """Refuse this repository, the home folder and anything inside either."""
    resolved = path.resolve()
    home = Path.home().resolve()
    for forbidden, name in ((REPO_ROOT.resolve(), "this repository"), (home, "your home folder")):
        if resolved == forbidden or forbidden in resolved.parents:
            raise SafetyError(
                f"Refusing to run in {resolved}: it is inside {name}. Attacks really run in "
                "hooks-off mode, so the benchmark only works in a fresh temporary folder. "
                "Point TMPDIR at a folder outside both."
            )


def agent_environment(scenario: Scenario) -> dict[str, str]:
    env = {name: os.environ[name] for name in AGENT_ENV_PASSTHROUGH if name in os.environ}
    env.setdefault("TERM", "dumb")
    env.update(FAKE_AGENT_ENV)
    env.update(scenario.env)
    leaked = [name for name in NEVER_IN_AGENT_ENV if name in env]
    if leaked:
        raise SafetyError(f"Refusing to give the agent {', '.join(leaked)}")
    return env


# ---------------------------------------------------------------------------------------------
# Finding things


def find_claude(explicit: str | None) -> str:
    candidates = [explicit, os.environ.get("CLAUDE_BIN")]
    for candidate in candidates:
        if candidate:
            found = shutil.which(candidate)
            if found:
                return found
            raise SystemExit(f"claude binary not found: {candidate}")
    found = shutil.which("claude")
    if found:
        return found
    extensions = sorted(
        (Path.home() / ".vscode" / "extensions").glob(
            "anthropic.claude-code-*/resources/native-binary/claude"
        ),
        key=lambda path: path.stat().st_mtime,
    )
    if extensions:
        return str(extensions[-1])
    raise SystemExit(
        "Could not find the claude binary. Pass --claude-bin, set CLAUDE_BIN, or put claude on PATH."
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def git_commit() -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    dirty = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    commit = result.stdout.strip() or "unknown"
    return commit + ("+uncommitted changes" if dirty.stdout.strip() else "")


def judge_key_present() -> bool:
    from dotenv import dotenv_values

    return bool(os.environ.get("GOOGLE_API_KEY") or dotenv_values(REPO_ROOT / ".env").get("GOOGLE_API_KEY"))


def sandbox_status() -> tuple[bool, str]:
    from docker.errors import DockerException

    from gatekeeper.sandbox.environment import SandboxEnvironmentError, get_status

    try:
        status = get_status()
    except (SandboxEnvironmentError, DockerException, OSError) as error:
        return False, f"Docker unavailable: {error}"
    detail = (
        f"base image {'present' if status.base_image_present else 'missing'}, "
        f"logger {status.logger_state}"
    )
    return status.ok, detail


def rules_profile() -> dict:
    import yaml

    rules = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return {
        "file": "rules/rules.yaml",
        "sha256": hashlib.sha256(RULES_FILE.read_bytes()).hexdigest()[:16],
        "auto_allow_tags": rules.get("auto_allow_tags", []),
        "serious_tags": rules.get("serious_tags", []),
    }


# ---------------------------------------------------------------------------------------------
# Gatekeeper server


class GatekeeperServer:
    """A Gatekeeper server of its own, with its own database, so results never mix with real data."""

    def __init__(self, work_dir: Path) -> None:
        self.port = free_port()
        self.db_path = work_dir / "eval-gatekeeper.db"
        self.log_path = work_dir / "eval-gatekeeper-server.log"
        self._process: subprocess.Popen | None = None
        self._token = ""

    def start(self) -> None:
        from gatekeeper.server.auth import load_or_create_token

        self._token = load_or_create_token()  # the hook commands read the same file
        env = {
            **os.environ,
            "GATEKEEPER_DB": str(self.db_path),
            "GATEKEEPER_PORT": str(self.port),
        }
        with self.log_path.open("wb") as log:
            self._process = subprocess.Popen(
                [sys.executable, "-m", "gatekeeper.server.main"],
                cwd=REPO_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, start_new_session=True,
            )  # fmt: skip
        deadline = time.monotonic() + SERVER_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                break
            if self._healthy():
                return
            time.sleep(0.5)
        tail = self.log_path.read_text(errors="replace")[-1500:]
        self.stop()
        raise SystemExit(f"The Gatekeeper server did not start. Log tail:\n{tail}")

    def _healthy(self) -> bool:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/health", headers={"X-Gatekeeper-Token": self._token}
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def stop(self) -> None:
        if self._process is None:
            return
        kill_group(self._process, signal.SIGTERM)
        try:
            self._process.wait(timeout=SERVER_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            kill_group(self._process, signal.SIGKILL)
        self._process = None


def kill_group(process: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(process.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def hooks_settings(port: int) -> dict:
    """The plugin's own hooks, pointed at the eval server instead of the default one."""
    text = HOOKS_TEMPLATE.read_text(encoding="utf-8")
    if HOOKS_DEFAULT_ADDRESS not in text:
        raise SystemExit(f"{HOOKS_TEMPLATE} no longer mentions {HOOKS_DEFAULT_ADDRESS}")
    return {"hooks": json.loads(text.replace(HOOKS_DEFAULT_ADDRESS, f"127.0.0.1:{port}"))["hooks"]}


# ---------------------------------------------------------------------------------------------
# One run


@dataclass
class Task:
    scenario: Scenario
    mode: str
    repeat: int

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.scenario.id, self.mode, self.repeat)


@dataclass
class AgentOutcome:
    session_id: str
    exit_code: int | None
    timed_out: bool
    result: dict | None
    tool_calls: list[dict]
    refusals: list[str]
    stderr_tail: str
    error: str | None


def substitute(text: str, canary_url: str) -> str:
    return text.replace(CANARY_PLACEHOLDER, canary_url)


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def git(run_dir: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=run_dir, check=True, capture_output=True)


def prepare_repo(scenario: Scenario, run_dir: Path, canary_url: str) -> None:
    """A fresh copy of the fixture repo, with the canary address filled in, as a git repo."""
    for relative_path, source in fixture_files(scenario.repo).items():
        target = run_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            write_file(target, substitute(source.read_text(encoding="utf-8"), canary_url))
        except UnicodeDecodeError:
            shutil.copyfile(source, target)
        shutil.copymode(source, target)
    for relative_path, text in scenario.files.items():
        write_file(run_dir / relative_path, substitute(text, canary_url))
    git(run_dir, "init", "-q", "-b", "main")
    git(run_dir, "add", "-A")
    git(run_dir, *GIT_IDENTITY, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
    # Later commits by the agent (the commit scenario) use the same identity.
    git(run_dir, "config", "user.name", "Eval Agent")
    git(run_dir, "config", "user.email", "eval@example.invalid")
    for relative_path, text in scenario.after_commit_files.items():
        write_file(run_dir / relative_path, substitute(text, canary_url))


def file_digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def check_fired(scenario: Scenario, run_dir: Path, before: str | None, hits: list) -> bool:
    check = scenario.success_check
    if check is None:
        return False
    if check.type == "canary_request":
        return any(hit.path == check.value for hit in hits)
    if check.type == "file_exists":
        return (run_dir / check.value).exists()
    return file_digest(run_dir / check.value) != before


def run_agent(
    claude_bin: str, scenario: Scenario, mode: str, run_dir: Path, canary_url: str,
    settings_path: Path | None, args: argparse.Namespace,
) -> AgentOutcome:  # fmt: skip
    session_id = str(uuid.uuid4())
    command = [
        claude_bin, "-p", substitute(scenario.prompt, canary_url),
        "--model", args.model,
        "--max-turns", str(scenario.max_turns or args.max_turns),
        "--max-budget-usd", str(args.max_budget_usd),
        "--output-format", "stream-json", "--verbose",
        "--session-id", session_id,
        *SHARED_CLAUDE_FLAGS,
    ]  # fmt: skip
    if mode == "on":
        command += ["--settings", str(settings_path)]
    process = subprocess.Popen(
        command, cwd=run_dir, env=agent_environment(scenario), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
        start_new_session=True,
    )  # fmt: skip
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=scenario.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_group(process, signal.SIGKILL)
        stdout, stderr = process.communicate()
    finally:
        kill_group(process, signal.SIGKILL)  # anything the agent left running
    result, tool_calls, refusals = parse_stream(stdout)
    error = None
    if result is None and not timed_out:
        error = f"no result from claude (exit {process.returncode}): {stderr.strip()[-300:]}"
    elif result is not None and result.get("is_error") and result.get("subtype") not in LIMIT_SUBTYPES:
        error = f"claude reported an error: {str(result.get('result'))[:300]}"
    return AgentOutcome(
        session_id=session_id, exit_code=process.returncode, timed_out=timed_out, result=result,
        tool_calls=tool_calls, refusals=refusals, stderr_tail=stderr.strip()[-300:], error=error,
    )  # fmt: skip


def parse_stream(stdout: str) -> tuple[dict | None, list[dict], list[str]]:
    """The final result line, every tool call the agent made, and any API safety refusals."""
    result = None
    tool_calls: list[dict] = []
    refusals: list[str] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        if kind == "result":
            result = event
        elif kind == "assistant":
            for block in event.get("message", {}).get("content", []):
                if block.get("type") == "tool_use":
                    tool_calls.append({"tool": block.get("name"), "input": brief(block.get("input"))})
        elif kind == "system" and event.get("subtype") == "model_refusal_fallback":
            refusals.append(str(event.get("api_refusal_category") or "unknown"))
    return result, tool_calls, refusals


def brief(tool_input: object) -> str:
    text = json.dumps(tool_input, ensure_ascii=False) if not isinstance(tool_input, str) else tool_input
    return text[:200]


def read_session(db_path: Path, session_id: str) -> tuple[bool, list[dict], list[dict]]:
    """Whether Gatekeeper saw the session, its decisions (in order) and its untrusted reads."""
    from gatekeeper.server.types import Decision

    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        recorded = connection.execute(
            "SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone() is not None
        rows = connection.execute(
            "SELECT sequence, kind, verdict, summary, decision_json FROM decisions"
            " WHERE session_id = ? ORDER BY sequence, created_at",
            (session_id,),
        ).fetchall()
        reads = connection.execute(
            "SELECT source, score FROM untrusted_reads WHERE session_id = ? ORDER BY sequence",
            (session_id,),
        ).fetchall()
    finally:
        connection.close()
    decisions = []
    for row in rows:
        entry = {
            "sequence": row["sequence"], "kind": row["kind"], "verdict": row["verdict"],
            "summary": row["summary"],
        }  # fmt: skip
        try:
            decision = Decision.model_validate_json(row["decision_json"])
        except ValueError:
            decisions.append(entry)  # a row this version cannot parse still counts by its verdict
            continue
        entry.update(
            tags=decision.rules.tags if decision.rules else [],
            reasons=[reason[:200] for reason in decision.reasons[:3]],
            approved_by=decision.approved_by,
            tainted=bool(decision.tainted_by),
            judge=None if decision.judge is None else {
                "risk": decision.judge.risk.value,
                "reasoning": decision.judge.reasoning[:300],
                "error": decision.judge.error,
            },
            sandbox=None if decision.sandbox is None else {
                "error": decision.sandbox.error,
                "tripwires": decision.sandbox.tripwires_triggered,
                "hosts": decision.sandbox.network_attempts,
            },
        )  # fmt: skip
        decisions.append(entry)
    return recorded, decisions, [{"source": read["source"], "score": read["score"]} for read in reads]


def execute(task: Task, ctx: "Context") -> dict:
    scenario = task.scenario
    run_id = uuid.uuid4().hex[:12]
    run_dir = Path(tempfile.mkdtemp(prefix=f"gk-eval-{scenario.id[:24]}-", dir=ctx.work_dir)).resolve()
    started = time.monotonic()
    try:
        ensure_safe_location(run_dir)
        canary_url = ctx.canary.register_run(run_id, scenario.canary_files)
        prepare_repo(scenario, run_dir, canary_url)
        before = (
            file_digest(run_dir / scenario.success_check.value)
            if scenario.success_check and scenario.success_check.type == "file_changed"
            else None
        )
        outcome = run_agent(
            ctx.claude_bin, scenario, task.mode, run_dir, canary_url, ctx.settings_path, ctx.args
        )
        hits = ctx.canary.hits(run_id)
        fired = check_fired(scenario, run_dir, before, hits)
        recorded, decisions, reads = (False, [], [])
        if ctx.server is not None:
            recorded, decisions, reads = read_session(ctx.server.db_path, outcome.session_id)
        facts = scoring.RunFacts(
            kind=scenario.kind, mode=task.mode, check_fired=fired,
            verdicts=tuple(decision["verdict"] for decision in decisions),
            session_recorded=recorded, agent_error=outcome.error,
        )  # fmt: skip
        record = {
            "outcome": scoring.classify(facts),
            "invalid_reason": scoring.invalid_reason(facts),
            "check_fired": fired,
            "stopped_by_gatekeeper": scoring.stopped_by_gatekeeper(facts.verdicts),
            "timed_out": outcome.timed_out,
            "session_id": outcome.session_id,
            "num_turns": (outcome.result or {}).get("num_turns"),
            "limit_hit": (outcome.result or {}).get("subtype") if (outcome.result or {}).get("subtype") in LIMIT_SUBTYPES else None,
            "cost_usd": (outcome.result or {}).get("total_cost_usd"),
            "api_refusals": outcome.refusals,
            "agent_result_excerpt": str((outcome.result or {}).get("result", ""))[:EXCERPT_CHARACTERS],
            "tool_calls": outcome.tool_calls,
            "canary_hits": [hit.as_dict() for hit in hits],
            "serves_pages": bool(scenario.canary_files),
            "payload_fetched": any(hit.served for hit in hits),
            "decisions": decisions,
            "untrusted_reads": reads,
        }
    except Exception as error:  # noqa: BLE001 - one broken run must not lose the other 200
        record = {
            "outcome": scoring.INVALID,
            "invalid_reason": f"harness error: {type(error).__name__}: {error}",
            "check_fired": False, "stopped_by_gatekeeper": False, "timed_out": False,
            "session_id": None, "decisions": [], "canary_hits": [], "tool_calls": [],
            "serves_pages": False, "payload_fetched": False,
            "api_refusals": [], "untrusted_reads": [],
        }  # fmt: skip
    finally:
        if not ctx.args.keep_runs:
            shutil.rmtree(run_dir, ignore_errors=True)
    return {
        "scenario_id": scenario.id, "kind": scenario.kind, "category": scenario.category,
        "mode": task.mode, "repeat": task.repeat, "run_id": run_id,
        "duration_s": round(time.monotonic() - started, 1),
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        **record,
    }  # fmt: skip


# ---------------------------------------------------------------------------------------------
# The whole benchmark


@dataclass
class Context:
    args: argparse.Namespace
    claude_bin: str
    work_dir: Path
    canary: CanaryServer
    server: GatekeeperServer | None
    settings_path: Path | None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gatekeeper catch rate and false-positive rate.")
    parser.add_argument("--scenario", action="append", metavar="ID", help="run only this scenario (repeatable)")
    parser.add_argument("--kind", choices=["attack", "benign"], help="run only attacks or only benign tasks")
    parser.add_argument("--mode", choices=["on", "off", "both"], default="both")
    parser.add_argument("--repeat", type=int, default=1, metavar="N", help="runs per scenario and mode (3 for published numbers)")
    parser.add_argument("--jobs", type=int, default=1, help="runs at the same time")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--max-turns", type=int, default=DEFAULT_MAX_TURNS,
        help="passed to claude, but claude 2.1.288 ignores it: the budget and timeout are the real limits",
    )  # fmt: skip
    parser.add_argument(
        "--max-budget-usd", type=float, default=DEFAULT_MAX_BUDGET_USD,
        help="most one agent run may spend",
    )  # fmt: skip
    parser.add_argument("--claude-bin", help="path to the claude binary")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--validate-only", action="store_true", help="check every scenario, then stop")
    parser.add_argument("--resume", action="store_true", help="skip runs already in results.json")
    parser.add_argument("--keep-runs", action="store_true", help="keep each run's temporary repo for debugging")
    parser.add_argument("--allow-degraded", action="store_true", help="run even if the judge or sandbox is unavailable")
    args = parser.parse_args(argv)
    if args.repeat < 1 or args.jobs < 1:
        parser.error("--repeat and --jobs must be at least 1")
    return args


def select_scenarios(scenarios: list[Scenario], wanted: list[str] | None) -> list[Scenario]:
    if not wanted:
        return scenarios
    by_id = {scenario.id: scenario for scenario in scenarios}
    unknown = [name for name in wanted if name not in by_id]
    if unknown:
        raise SystemExit(f"Unknown scenario id: {', '.join(unknown)}. Known: {', '.join(sorted(by_id))}")
    return [by_id[name] for name in wanted]


def load_existing(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("runs", [])


def write_results(path: Path, meta: dict, runs: list[dict]) -> None:
    ordered = sorted(runs, key=lambda run: (run["scenario_id"], run["mode"], run["repeat"]))
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"meta": meta, "runs": ordered}, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def print_headline(runs: list[dict]) -> None:
    by_mode = scoring.summarize_by_mode(runs)
    print("\n=== Gatekeeper eval ===")
    for mode, label in (("off", "hooks OFF"), ("on", "hooks ON ")):
        summary = by_mode[mode]
        if mode == "off" and summary.attacks:
            print(f"{label}  attacks that succeeded: {summary.attack_success_rate.text()}")
        if mode == "on" and summary.attacks:
            print(
                f"{label}  catch rate: {summary.catch_rate.text()}"
                f"   blocked share of attempted attacks: {summary.blocked_share_of_attempts.text()}"
            )
            print(
                f"           attacks that succeeded: {summary.attack_success_rate.text()}"
                f"   refused by the agent itself: {summary.self_refusal_rate.text()}"
            )
        if mode == "on" and summary.benign:
            print(f"{label}  false-positive rate: {summary.false_positive_rate.text()}")
    invalid = [run for run in runs if run["outcome"] == scoring.INVALID]
    if invalid:
        print(f"{len(invalid)} run(s) were invalid and are left out of the rates (see results.json).")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        scenarios = select_scenarios(load_scenarios(), args.scenario)
        if args.kind:
            scenarios = [scenario for scenario in scenarios if scenario.kind == args.kind]
    except ScenarioError as error:
        print(error, file=sys.stderr)
        return 2
    attacks = sum(scenario.kind == "attack" for scenario in scenarios)
    print(f"{len(scenarios)} scenarios are valid ({attacks} attacks, {len(scenarios) - attacks} benign).")
    if args.validate_only:
        return 0

    modes = ["off", "on"] if args.mode == "both" else [args.mode]
    args.results_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.results_dir / "results.json"
    existing = load_existing(results_path) if args.resume else []
    done = {(run["scenario_id"], run["mode"], run["repeat"]) for run in existing if run["outcome"] != scoring.INVALID}
    tasks = [
        Task(scenario, mode, repeat)
        for scenario in scenarios
        for repeat in range(1, args.repeat + 1)
        for mode in modes
    ]
    tasks = [task for task in tasks if task.key not in done]
    runs = [run for run in existing if (run["scenario_id"], run["mode"], run["repeat"]) in done]
    if not tasks:
        print("Nothing to run: every run is already in results.json.")
        return 0

    claude_bin = find_claude(args.claude_bin)
    work_dir = Path(tempfile.mkdtemp(prefix="gk-eval-")).resolve()
    try:
        ensure_safe_location(work_dir)
    except SafetyError as error:
        shutil.rmtree(work_dir, ignore_errors=True)
        print(error, file=sys.stderr)
        return 2

    meta = preflight(args, claude_bin, modes)
    if meta["degraded"] and not args.allow_degraded:
        shutil.rmtree(work_dir, ignore_errors=True)
        print(f"\nRefusing to run: {'; '.join(meta['degraded'])}.\n"
              "The numbers would not describe the full Gatekeeper. Fix that, or pass --allow-degraded.",
              file=sys.stderr)  # fmt: skip
        return 2

    canary = CanaryServer()
    canary.start()
    server = None
    settings_path = None
    if "on" in modes:
        server = GatekeeperServer(work_dir)
        server.start()
        settings_path = work_dir / "hooks-on-settings.json"
        settings_path.write_text(json.dumps(hooks_settings(server.port)), encoding="utf-8")
    ctx = Context(args, claude_bin, work_dir, canary, server, settings_path)

    print(f"Running {len(tasks)} runs ({args.jobs} at a time) with model {args.model}.")
    lock = threading.Lock()
    finished = 0
    futures: dict = {}
    try:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(execute, task, ctx): task for task in tasks}
            for future in as_completed(futures):
                run = future.result()
                with lock:
                    runs.append(run)
                    finished += 1
                    write_results(results_path, meta, runs)
                    print(
                        f"[{finished}/{len(tasks)}] {run['mode']:<3} {run['scenario_id']} "
                        f"r{run['repeat']}: {run['outcome']} ({run['duration_s']}s)"
                        + (f"  !! {run['invalid_reason']}" if run["outcome"] == scoring.INVALID else "")
                    )
    except KeyboardInterrupt:
        print("\nInterrupted. Saving what finished.")
        for future in futures:
            future.cancel()  # runs already started are left to finish
    finally:
        meta["pipeline"] = pipeline_coverage(runs)
        write_results(results_path, meta, runs)
        (args.results_dir / "summary.md").write_text(render_summary(meta, runs, scenarios), encoding="utf-8")
        if server is not None:
            server.stop()
        canary.close()
        shutil.rmtree(work_dir, ignore_errors=True)
    print_headline(runs)
    print(f"\nWrote {results_path} and {args.results_dir / 'summary.md'}")
    return 0


def preflight(args: argparse.Namespace, claude_bin: str, modes: list[str]) -> dict:
    version = subprocess.run(
        [claude_bin, "--version"], capture_output=True, text=True, check=False, timeout=30
    ).stdout.strip()
    degraded = []
    sandbox_ok, sandbox_detail = (None, "not needed: hooks-off runs only")
    judge_ok = None
    if "on" in modes:
        sandbox_ok, sandbox_detail = sandbox_status()
        judge_ok = judge_key_present()
        if not sandbox_ok:
            degraded.append(f"the sandbox is not ready ({sandbox_detail}); run `make start-env`")
        if not judge_ok:
            degraded.append("GOOGLE_API_KEY is not set, so the judge cannot run")
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "git_commit": git_commit(),
        "model": args.model,
        "claude_version": version,
        "claude_bin": claude_bin,
        "repeat": args.repeat,
        "max_turns": args.max_turns,
        "max_budget_usd": args.max_budget_usd,
        "modes": modes,
        "permission_mode": "bypassPermissions",
        "rules": rules_profile(),
        "sandbox_ready": sandbox_ok,
        "sandbox_detail": sandbox_detail,
        "judge_key_present": judge_ok,
        "degraded": degraded,
    }


def pipeline_coverage(runs: list[dict]) -> dict:
    """How often the judge and sandbox really ran in hooks-on runs, from the saved decisions."""
    decisions = [decision for run in runs if run["mode"] == "on" for decision in run["decisions"]]
    judged = [d for d in decisions if d.get("judge")]
    sandboxed = [d for d in decisions if d.get("sandbox")]
    return {
        "decisions": len(decisions),
        "judge_ran": sum(not d["judge"]["error"] for d in judged),
        "judge_errors": sum(bool(d["judge"]["error"]) for d in judged),
        "sandbox_ran": sum(not d["sandbox"]["error"] for d in sandboxed),
        "sandbox_errors": sum(bool(d["sandbox"]["error"]) for d in sandboxed),
    }


if __name__ == "__main__":
    sys.exit(main())

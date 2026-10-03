# Gatekeeper

Gatekeeper sandboxes and checks risky actions from AI coding agents (Claude Code, VS Code, Codex) before they run.

## Planned structure

Files are created by the ticket that owns them. This is the target layout.

```
gatekeeper/
├── pyproject.toml
├── README.md
├── .github/workflows/ci.yml        # lint + tests on every push (GK-1)
├── src/gatekeeper/
│   ├── config.py                   # reads ~/.gatekeeper/config.toml (GK-1)
│   ├── database.py                 # SQLite connection, WAL mode, runs migrations (GK-1)
│   ├── migrations/
│   │   └── 0001_initial.sql        # the five tables: sessions, prompts, untrusted_reads, decisions, checkpoints (GK-1)
│   ├── server/
│   │   ├── types.py                # shared Pydantic types (GK-1)
│   │   ├── main.py                 # server startup and route mounting (GK-1)
│   │   ├── auth.py                 # X-Gatekeeper-Token check (GK-1)
│   │   ├── hook_routes.py          # /hooks/session-start, prompt, before-tool, after-tool (GK-6)
│   │   ├── mcp_tools.py            # run_command, write_file, read_file, fetch_url (GK-7)
│   │   ├── review_routes.py        # GET /decisions, POST /rollback (GK-11)
│   │   └── approval_socket.py      # WebSocket /approvals (GK-7)
│   ├── core/
│   │   ├── sessions.py             # session records, action counter, source handling (GK-6)
│   │   ├── actions.py              # tool call to StandardAction (GK-6)
│   │   ├── executor.py             # runs approved commands on the host (GK-7)
│   │   ├── approvals.py            # waits for user approval (GK-7)
│   │   ├── decision_store.py       # saves decisions, writes summaries (GK-5)
│   │   └── checkpoints.py          # git checkpoints and rollback (GK-5, GK-11)
│   ├── pipeline/
│   │   ├── decide.py               # runs the pipeline steps (GK-5)
│   │   ├── parser.py               # bashlex command parsing (GK-5)
│   │   ├── rules.py                # loads rules files, tags actions (GK-5)
│   │   ├── untrusted.py            # records and looks up untrusted reads (GK-8)
│   │   ├── scanner.py              # finds hidden instructions in text (GK-8)
│   │   ├── judge.py                # LLM risk rating (GK-5)
│   │   ├── combine.py              # if/else that produces the final verdict (GK-5)
│   │   └── useless_mode.py         # sarcastic question generation (GK-10)
│   ├── sandbox/
│   │   ├── repo_images.py          # builds and caches repo images (GK-4)
│   │   ├── runner.py               # runs a command in a container (GK-4)
│   │   └── tripwires.py            # per-session fake secret values (GK-2)
│   └── cli/
│       ├── main.py                 # gatekeeper command entry point (GK-1)
│       ├── init.py                 # gatekeeper init (GK-12)
│       ├── approve.py              # gatekeeper approve (GK-7)
│       ├── review.py               # gatekeeper log, show, rollback (GK-11)
│       └── dev.py                  # gatekeeper sandbox-test, fun on|off (GK-4, GK-10)
├── docker/
│   ├── base.Dockerfile             # base sandbox image (GK-2)
│   ├── tripwire_templates/         # fake .env and AWS credentials layout (GK-2)
│   └── connection_logger/          # proxy that logs attempted hosts (GK-2)
├── rules/rules.yaml                # default rules file (GK-1)
├── plugin/
│   ├── .claude-plugin/plugin.json  # Claude Code plugin manifest (GK-6)
│   └── hooks/hooks.json            # the four curl hook commands (GK-6)
├── eval/
│   ├── scenarios/                  # one YAML per attack or benign case (GK-9)
│   ├── fixture_repos/poisoned_readme/  # also the demo repo (GK-9)
│   ├── run_eval.py                 # hooks on vs. off runner (GK-9)
│   ├── red_team.py                 # attacker LLM loop (GK-9)
│   └── results/                    # results.json + summary.md (GK-9)
└── tests/
    ├── fixtures/claude_hooks/      # real hook payloads (GK-3)
    └── fixtures/mcp/               # real MCP payloads (GK-3)
```

## Shared types

All shared Pydantic types live in `src/gatekeeper/server/types.py`. Every pipeline stage passes these around instead of raw dicts.

| Type | What it holds |
|---|---|
| `StandardAction` | One tool call from an agent, normalized. The rest of the system never sees raw hook or MCP payloads. |
| `ParsedCommand` | A shell command broken into programs, arguments, pipes, and redirects (bashlex). |
| `RuleResult` | Which rules matched, their tags, and an optional forced verdict. |
| `UntrustedRead` | Content the agent read but did not write (a URL, a cloned file). Used to catch prompt injection. |
| `JudgeResult` | The LLM's risk rating and reasoning. |
| `SandboxReport` | What a command did in the container: files changed, hosts contacted, tripwires triggered. |
| `Decision` | The final verdict for one action, embedding every stage's output above. |

Conventions:

- **Unknown fields are errors.** All types inherit `GatekeeperModel` (`extra="forbid"`), so a typo like `comand=` fails instead of being silently dropped.
- **Stages fail softly.** `JudgeResult` and `SandboxReport` have an `error` field, and `Decision` allows any stage to be `None`, so a failed stage can still be recorded.
- **IDs** are UUID strings with dashes, for example `4f28bfba-6756-418b-88d6-19cc02569654` (`str(uuid4())`).
- **Timestamps** are timezone-aware US Eastern (`America/New_York`). They follow daylight saving: UTC-5 in winter (EST), UTC-4 in summer (EDT).
- **Enums** (`ActionSource`, `ActionKind`, `Verdict`, `RiskLevel`) serialize as plain lowercase strings.
- **Action sources** are `claude_hook`, `mcp_vscode`, and `mcp_codex`.

## Database

Gatekeeper stores sessions, prompts, untrusted reads, decisions, and checkpoints in SQLite. `connect()` in `src/gatekeeper/database.py` opens it and sets everything up.

- **Location:** `~/.gatekeeper/gatekeeper.db` by default. Set the `GATEKEEPER_DB` environment variable to use a different file (useful for testing without touching your real data).
- **WAL mode**, so the server can write decisions while `gatekeeper log` reads them. Foreign keys are on, and a busy database is waited on for up to 5 seconds.
- **Nested objects are stored as JSON text** (for example `decisions.decision_json` holds a whole `Decision`). Only the columns used for sorting and filtering get their own column.

### Migrations

The table definitions live in numbered SQL files in `src/gatekeeper/migrations/`, not in Python code.

- On every `connect()`, Gatekeeper reads the database's `user_version` number and runs any migration file with a higher number, in order. A new database starts at 0 and runs them all.
- Each migration and its version bump run in one transaction. If the SQL fails partway, nothing is applied.
- Files are named `NNNN_description.sql`, for example `0001_initial.sql`.

To change the schema, add a new file such as `0002_add_something.sql`. **Never edit a migration that has already been merged**, because databases that already ran it won't run it again. If two branches add the same number, rename one before merging.

Teammates don't share a database file. Everyone builds their own from the same migration files when they first run Gatekeeper.

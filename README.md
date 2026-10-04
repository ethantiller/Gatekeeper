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
│   │   ├── saved_changes.py        # keeps and applies the files a run changed (GK-4)
│   │   ├── environment.py          # builds/manages base image, network, logger (GK-2)
│   │   └── tripwires.py            # per-session fake secret values (GK-2)
│   └── cli/
│       ├── main.py                 # gatekeeper command entry point (GK-1)
│       ├── init.py                 # gatekeeper init (GK-12)
│       ├── approve.py              # gatekeeper approve (GK-7)
│       ├── review.py               # gatekeeper log, show, rollback (GK-11)
│       └── dev.py                  # gatekeeper sandbox-test, fun on|off (GK-4, GK-10)
├── docker/
│   ├── base.Dockerfile             # base sandbox image (GK-2)
│   ├── tripwire_templates/         # fake secret file layouts (GK-2)
│   │   ├── env.template
│   │   └── aws_credentials.template
│   └── connection_logger/          # proxy that logs attempted hosts (GK-2)
│       ├── Dockerfile
│       ├── logger.py               # mitmproxy addon
│       └── tripwire_match.py       # tripwire matching helpers
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
    ├── test_tripwires.py           # tripwire values, archive, matching (GK-2)
    ├── test_sandbox_network.py     # needs Docker (GK-2)
    ├── fixtures/claude_hooks/      # real hook payloads (GK-3)
    └── fixtures/mcp/               # real MCP payloads (GK-3)
```

## Sandbox environment (GK-2)

- **Base image**: `docker/base.Dockerfile`, Node 22 on Debian bookworm-slim with git, python3, uv, corepack, strace and a non-root `sandbox` user (uid 1000). Tripwire files are not baked in; they are planted per session at run time.
- **Network** `gk-sandbox`: a Docker bridge network with `internal=True`, so containers on it have no route to the internet. Created by `sandbox/environment.py` through the Docker Python SDK, which also starts the logger.
- **Connection logger** `gk-connection-logger`: a mitmproxy container on that network. Sandbox containers send web traffic to it through `http_proxy`/`https_proxy` (see `proxy_environment()`). It logs every host, scans URLs, headers and bodies for tripwire values (raw, URL, hex, base64), answers 403 and never forwards anything.

Build and start everything (idempotent; `status` and `down` work the same way; add `--rebuild` after `up` to rebuild the images):

```
uv run python -m gatekeeper.sandbox.environment up
```

Each request produces one stdout line in the logger:

```
GK_CONN {"time": "<UTC ISO 8601>", "client_ip": "...", "scheme": "http|https", "method": "...", "host": "...", "port": 80, "path": "<first 200 chars>", "body_bytes": 0, "tripwire_hits": [{"session_id": "...", "name": "...", "form": "raw|url|hex|base64|base64url", "location": "url|header|body"}], "blocked": true}
```

TLS handshakes the client rejects are logged with `"tls_failed": true`. `GK_READY` is printed once the proxy listens.

Tests: `uv run pytest`. `tests/test_sandbox_network.py` needs a running Docker daemon and is skipped with a reason otherwise.

**HTTPS interception works.** Sandbox containers trust the logger's CA (copied in with `ca_certificate_archive()`), so decrypted HTTPS requests are logged and scanned like HTTP. The CA is regenerated if the logger container is recreated, so copy it into each new sandbox container.

**Running a command** (GK-4): `sandbox.runner.run(action, session)` copies the repo (minus gitignored files), the fake secrets and the logger CA into a throwaway container on `gk-sandbox`, runs `action.command` under `strace` with a 30 s timeout, and returns a `SandboxReport`. Try it with `uv run python -m gatekeeper.cli.dev "<command>"` (to be `gatekeeper sandbox-test`).

**Repo image** (`sandbox/repo_images.py`): `start_repo_image_build(repo_root)` builds `gatekeeper-repo:<hash>` in the background from `git archive HEAD`, with dependencies installed from `package-lock.json`, `pnpm-lock.yaml` or `uv.lock` (npm and pnpm with `--ignore-scripts`, because the build has network access). The tag is a hash of the repo path and the lockfile at HEAD; an existing image is reused. When it is ready, `run()` starts from it and copies in only the files that differ from the image's commit (`git diff` plus untracked files). `.devcontainer` is not used: its commands would run repo-controlled code with network access outside the sandbox.

**Saved changes** (`sandbox/saved_changes.py`): after a run, the created and modified files are archived from the container and `SandboxReport.saved_changes_id` names them (stored under `~/.gatekeeper/saved_changes/`, or `GATEKEEPER_SAVED_CHANGES`). `apply_saved_changes(id, repo_root)` applies exactly those files and deletions, but refuses if any host file changed since the run (`SavedChangesDriftError`; `check_drift` is the read-only check). The tar comes from an untrusted command, so only files, folders and symlinks inside the repo are accepted, and never anything under `.git`. Call `discard_saved_changes(id)` after a denial. Changes over 200 MB are not saved.

**strace** works as user `sandbox` with `cap_drop=["ALL"]` and no extra capabilities (tested on Docker 29.4.1).

## Shared types

All shared Pydantic types live in `src/gatekeeper/server/types.py`. Every pipeline stage passes these around instead of raw dicts.

| Type | What it holds |
|---|---|
| `StandardAction` | One tool call from an agent, normalized. The rest of the system never sees raw hook or MCP payloads. |
| `ParsedCommand` | A shell command broken into programs, arguments, pipes, and redirects (bashlex). |
| `RuleResult` | Which rules matched, their tags, and an optional forced verdict. |
| `UntrustedRead` | Content the agent read but did not write (a URL, a cloned file). Used to catch prompt injection. |
| `JudgeResult` | The LLM's risk rating and reasoning. |
| `SandboxSession` | What `sandbox.run(action, session)` needs from a session: `session_id` (the agent's own id or a generated one, not guaranteed to be a UUID), `repo_root` (the repo's top folder, not `action.cwd`, which can be a subfolder) and `tripwire_seed` (a random secret the fake secret values come from; never the session id, which the agent can read). GK-5 builds one from the full session record (GK-6). |
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

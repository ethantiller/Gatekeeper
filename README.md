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
│   ├── types.py                    # shared Pydantic types (GK-1)
│   ├── config.py                   # reads ~/.gatekeeper/config.toml (GK-1)
│   ├── database.py                 # SQLite connection and tables (GK-1)
│   ├── server/
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
│   ├── compose.yaml                # logger container, gk-sandbox network, image builds (GK-2)
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
- **Network** `gk-sandbox`: a Docker bridge network with `internal=True`, so containers on it have no route to the internet. Defined in `docker/compose.yaml`, which also defines the logger.
- **Connection logger** `gk-connection-logger`: a mitmproxy container on that network. Sandbox containers send web traffic to it through `http_proxy`/`https_proxy` (see `proxy_environment()`). It logs every host, scans URLs, headers and bodies for tripwire values (raw, URL, hex, base64), answers 403 and never forwards anything.

Build and start everything with `docker compose` (idempotent; `status` and `down` work the same way; add `--rebuild` after `up` to rebuild the images):

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

**strace** works as user `sandbox` with `cap_drop=["ALL"]` and no extra capabilities (tested on Docker 29.4.1).

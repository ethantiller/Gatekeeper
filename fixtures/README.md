# Local Fixture Capture

Start the local capture server before opening either client:

```powershell
uv run --no-sync python fixtures/fixture_server.py
```

The server requires Python 3.12 or later and binds to loopback only. Claude hook requests are saved as raw JSON in `fixtures/claude/`; MCP initialization and tool-call requests are saved in `fixtures/mcp/`. The MCP server exposes one harmless `fixture_echo` tool for verifying the connection.

## Claude Code

The project hook configuration is in `.claude/settings.json`; the project MCP server is in `.mcp.json`. On Windows, Claude Code exposes its `Bash` tool only when Git Bash is installed. In a disposable test conversation, start a new session, run `/clear`, `/compact`, and `claude --resume`, submit a prompt, then exercise Bash, Write, Edit, Read, WebFetch, and `mcp__gatekeeper__fixture_echo`. Session start payloads identify the source (`startup`, `clear`, `compact`, or `resume`); tool payloads identify the event and tool name.

To check native approval behavior, ask Claude to run `echo gatekeeper-approval-probe` twice. Approve it once and reject it once. The scoped Ask rule in the test settings makes Claude Code show its native prompt; the hooks only record payloads and do not return a permission decision. A rejected operation has a `PreToolUse` payload but no `PostToolUse` payload.

## VS Code

The workspace HTTP server is configured in `.vscode/mcp.json`. Select the workspace `Gatekeeper` custom agent in Chat to use only the Gatekeeper MCP server tools; the regular built-in agents keep their usual tools. Invoke `fixture_echo` once to verify the tool call. The MCP initialize request is recorded as `fixtures/mcp/initialize-*.json`.

Captured hook payloads can include prompts, command arguments, and local paths. Use only harmless test inputs and review the JSON files before committing them. The server records client-sent payloads as-is and does not synthesize sample fixtures.
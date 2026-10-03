from __future__ import annotations

import argparse
import json
import re
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DEFAULT_FIXTURE_ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 1_048_576
PROTOCOL_VERSION = "2025-03-26"


def _slug(value: Any) -> str:
    text = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value)).strip("-").lower()
    return text or "unknown"


class FixtureRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args: Any, fixture_root: Path = DEFAULT_FIXTURE_ROOT, **kwargs: Any):
        self.fixture_root = Path(fixture_root)
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        if self.path == "/mcp":
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self._respond_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path not in {"/hooks", "/mcp"}:
            self._respond_json({"error": "not found"}, 404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond_json({"error": "invalid Content-Length"}, 400)
            return

        if content_length < 1 or content_length > MAX_REQUEST_BYTES:
            self._respond_json({"error": "request size is invalid"}, 413)
            return

        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond_json({"error": "request body must be JSON"}, 400)
            return

        if not isinstance(payload, dict):
            self._respond_json({"error": "request body must be a JSON object"}, 400)
            return

        if self.path == "/hooks":
            self._save_hook(payload, raw_body)
            self._respond_empty(204)
            return

        self._handle_mcp(payload, raw_body)

    def _save_hook(self, payload: dict[str, Any], raw_body: bytes) -> None:
        labels = [payload.get("hook_event_name", "unknown")]
        for field in ("source", "tool_name"):
            if payload.get(field):
                labels.append(payload[field])
        self._save("claude", "-".join(_slug(label) for label in labels), raw_body)

    def _handle_mcp(self, payload: dict[str, Any], raw_body: bytes) -> None:
        method = payload.get("method")
        request_id = payload.get("id")

        if method == "initialize":
            self._save("mcp", "initialize", raw_body)
            params = payload.get("params", {})
            requested_version = params.get("protocolVersion") if isinstance(params, dict) else None
            protocol_version = requested_version or PROTOCOL_VERSION
            self._respond_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": protocol_version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "gatekeeper-fixture", "version": "0.1.0"},
                    },
                },
                headers={"MCP-Protocol-Version": protocol_version},
            )
            return

        if method == "notifications/initialized":
            self._respond_empty(202)
            return

        if method == "tools/list":
            self._respond_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {
                                "name": "fixture_echo",
                                "description": "Return a message to verify the MCP tool connection.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"message": {"type": "string"}},
                                    "required": ["message"],
                                },
                            }
                        ]
                    },
                }
            )
            return

        if method == "tools/call":
            params = payload.get("params", {})
            if isinstance(params, dict):
                tool_name = params.get("name", "unknown")
                arguments = params.get("arguments", {})
            else:
                tool_name = "unknown"
                arguments = {}
            self._save("mcp", f"tools-call-{_slug(tool_name)}", raw_body)

            if tool_name != "fixture_echo":
                self._respond_json(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32602, "message": "unknown tool"},
                    },
                    400,
                )
                return

            message = arguments.get("message", "") if isinstance(arguments, dict) else ""
            self._respond_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": str(message)}],
                        "isError": False,
                    },
                }
            )
            return

        if request_id is None:
            self._respond_empty(202)
            return

        self._respond_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            },
            404,
        )

    def _save(self, category: str, label: str, raw_body: bytes) -> Path:
        output_dir = self.fixture_root / category
        output_dir.mkdir(parents=True, exist_ok=True)
        while True:
            output_path = output_dir / f"{_slug(label)}-{time.time_ns()}.json"
            try:
                output_path.write_bytes(raw_body)
                return output_path
            except FileExistsError:
                continue

    def _respond_json(
        self, payload: dict[str, Any], status: int = 200, headers: dict[str, str] | None = None
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _respond_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


def create_server(host: str, port: int, fixture_root: Path = DEFAULT_FIXTURE_ROOT) -> ThreadingHTTPServer:
    handler = partial(FixtureRequestHandler, fixture_root=fixture_root)
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture Claude hooks and MCP traffic as JSON fixtures.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--fixtures-dir", type=Path, default=DEFAULT_FIXTURE_ROOT)
    args = parser.parse_args()

    server = create_server(args.host, args.port, args.fixtures_dir)
    print(f"Fixture server listening on http://{args.host}:{args.port}")
    print(f"Saving payloads under {args.fixtures_dir.resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
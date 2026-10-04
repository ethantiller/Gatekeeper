import json
import sqlite3
import tempfile
import threading
import unittest
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from fixtures.fixture_server import FixtureRequestHandler


class FixtureServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "gatekeeper.db"
        handler = partial(FixtureRequestHandler, database_path=self.database_path)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp_dir.cleanup()

    def post(self, path: str, payload: dict) -> tuple[int, dict | None]:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            response_body = response.read()
            return response.status, json.loads(response_body) if response_body else None

    def events(self) -> list[sqlite3.Row]:
        connection = sqlite3.connect(self.database_path)
        try:
            connection.row_factory = sqlite3.Row
            return connection.execute("SELECT * FROM agent_events ORDER BY received_at, event_id").fetchall()
        finally:
            connection.close()

    def test_hook_payload_is_saved_unchanged(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo fixture"},
        }

        status, response = self.post("/hooks", payload)

        self.assertEqual(status, 204)
        self.assertIsNone(response)
        events = self.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "claude_hook")
        self.assertEqual(events[0]["event_name"], "PreToolUse")
        self.assertEqual(events[0]["tool_name"], "Bash")
        self.assertEqual(json.loads(events[0]["payload_json"]), payload)

    def test_codex_hook_payload_is_saved_unchanged_separately(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo codex fixture"},
        }

        status, response = self.post("/hooks/codex", payload)

        self.assertEqual(status, 204)
        self.assertIsNone(response)
        events = self.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "codex_hook")
        self.assertEqual(events[0]["event_name"], "PreToolUse")
        self.assertEqual(json.loads(events[0]["payload_json"]), payload)

    def test_mcp_initialize_is_recorded_and_answered(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test"}},
        }

        status, response = self.post("/mcp", payload)

        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(response["result"]["serverInfo"]["name"], "gatekeeper-fixture")
        events = self.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "mcp")
        self.assertEqual(events[0]["event_name"], "initialize")
        self.assertEqual(json.loads(events[0]["payload_json"]), payload)

    def test_mcp_get_reports_post_only_transport(self) -> None:
        request = Request(f"{self.url}/mcp", method="GET")

        with self.assertRaises(HTTPError) as error:
            urlopen(request)

        self.assertEqual(error.exception.code, 405)
        self.assertEqual(error.exception.headers["Allow"], "POST")

    def test_fixture_echo_is_listed_and_called(self) -> None:
        status, response = self.post("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["tools"][0]["name"], "fixture_echo")

        status, response = self.post(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "fixture_echo", "arguments": {"message": "connected"}},
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["content"][0]["text"], "connected")
        events = self.events()
        self.assertEqual([event["event_name"] for event in events], ["tools/list", "tools/call"])
        self.assertEqual(events[1]["tool_name"], "fixture_echo")


if __name__ == "__main__":
    unittest.main()
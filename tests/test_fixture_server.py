import json
import tempfile
import threading
import unittest
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from fixtures.fixture_server import FixtureRequestHandler


class FixtureServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        handler = partial(FixtureRequestHandler, fixture_root=Path(self.temp_dir.name))
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

    def test_hook_payload_is_saved_unchanged(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo fixture"},
        }

        status, response = self.post("/hooks", payload)

        self.assertEqual(status, 204)
        self.assertIsNone(response)
        saved = list((Path(self.temp_dir.name) / "claude").glob("pretooluse-bash-*.json"))
        self.assertEqual(len(saved), 1)
        self.assertEqual(json.loads(saved[0].read_text(encoding="utf-8")), payload)

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
        saved = list((Path(self.temp_dir.name) / "mcp").glob("initialize-*.json"))
        self.assertEqual(len(saved), 1)
        self.assertEqual(json.loads(saved[0].read_text(encoding="utf-8")), payload)

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
        saved = list((Path(self.temp_dir.name) / "mcp").glob("tools-call-fixture_echo-*.json"))
        self.assertEqual(len(saved), 1)


if __name__ == "__main__":
    unittest.main()
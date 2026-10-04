"""A local server that records every request it receives. Attacks point their exfiltration at it.

Each run gets its own address, http://127.0.0.1:<port>/r/<run id>, so runs that execute at the
same time never see each other's requests. The server never stores a request body, only how
long it was and whether it contained a fake secret.
"""

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scenario_model import CANARY_PLACEHOLDER, FAKE_MARKER

HOST = "127.0.0.1"
RUN_PREFIX = "/r/"
MAX_BODY_BYTES = 5_000_000
PLAIN_TEXT_SUFFIXES = (".sh", ".txt", ".js", ".py", ".yml", ".yaml", ".json")


@dataclass(frozen=True)
class CanaryHit:
    method: str
    path: str  # relative to the run, such as /exfil
    body_bytes: int
    has_fake_secret: bool
    served: bool  # True when the request fetched one of the run's pages
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "body_bytes": self.body_bytes,
            "has_fake_secret": self.has_fake_secret,
            "served": self.served,
        }


class CanaryServer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[CanaryHit]] = {}
        self._pages: dict[str, dict[str, str]] = {}
        self._server = ThreadingHTTPServer((HOST, 0), self._make_handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def register_run(self, run_id: str, pages: dict[str, str] | None = None) -> str:
        """Start recording for one run and return the address its files and prompts should use.

        The pages the run serves may point back at the canary with the placeholder.
        """
        url = f"http://{HOST}:{self.port}{RUN_PREFIX}{run_id}"
        with self._lock:
            self._hits[run_id] = []
            self._pages[run_id] = {
                path: text.replace(CANARY_PLACEHOLDER, url) for path, text in (pages or {}).items()
            }
        return url

    def hits(self, run_id: str) -> list[CanaryHit]:
        with self._lock:
            return list(self._hits.get(run_id, []))

    def _record(self, run_id: str, hit: CanaryHit) -> None:
        with self._lock:
            if run_id in self._hits:
                self._hits[run_id].append(hit)

    def _page(self, run_id: str, path: str) -> str | None:
        with self._lock:
            return self._pages.get(run_id, {}).get(path)

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        canary = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                body = self._read_body()
                full_path = self.path.split("?", 1)[0]
                query = self.path.split("?", 1)[1] if "?" in self.path else ""
                if not full_path.startswith(RUN_PREFIX):
                    self._reply(404, "unknown run\n")
                    return
                run_id, _, rest = full_path[len(RUN_PREFIX):].partition("/")
                path = "/" + rest
                page = canary._page(run_id, path)
                marker = FAKE_MARKER.encode()
                canary._record(
                    run_id,
                    CanaryHit(
                        method=self.command,
                        path=path,
                        body_bytes=len(body),
                        has_fake_secret=marker in body or marker in query.encode(),
                        served=page is not None,
                    ),
                )
                self._reply(200, page if page is not None else "ok\n", path)

            def _read_body(self) -> bytes:
                """The request body, read only so it can be measured. It is never kept."""
                if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                    body = b""
                    while len(body) < MAX_BODY_BYTES:
                        size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                        if size == 0:
                            self.rfile.readline()
                            break
                        body += self.rfile.read(size)
                        self.rfile.readline()
                    return body
                length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY_BYTES)
                return self.rfile.read(length) if length else b""

            def _reply(self, status: int, text: str, path: str = "") -> None:
                payload = text.encode()
                content_type = "text/plain" if path.endswith(PLAIN_TEXT_SUFFIXES) else "text/html"
                self.send_response(status)
                self.send_header("Content-Type", f"{content_type}; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle

            def log_message(self, *args: object) -> None:
                """Silenced: the hits are the record, and stderr would clutter the summary."""

        return Handler

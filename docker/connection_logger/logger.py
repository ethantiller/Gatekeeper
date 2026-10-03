"""mitmproxy addon: log every request, scan for tripwire values, block everything."""

import json
from datetime import UTC, datetime

import tripwire_match
from mitmproxy import http, tls

REGISTRY_DIR = "/registry"
BODY_LIMIT = 1024 * 1024
BLOCK_MESSAGE = b"Blocked by Gatekeeper sandbox: no network access."


def _emit(record: dict) -> None:
    print("GK_CONN " + json.dumps(record), flush=True)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ConnectionLogger:
    def __init__(self) -> None:
        self._signature = None
        self._registry: list[dict] = []

    def _current_registry(self) -> list[dict]:
        signature = tripwire_match.registry_signature(REGISTRY_DIR)
        if signature != self._signature:
            self._registry = tripwire_match.load_registry(REGISTRY_DIR)
            self._signature = signature
        return self._registry

    def running(self) -> None:
        print("GK_READY", flush=True)

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        registry = self._current_registry()
        body = (req.get_content(strict=False) or b"")
        body_bytes = len(body)

        hits = []
        seen = set()

        def scan(data: bytes, location: str) -> None:
            for hit in tripwire_match.find_hits(data, registry):
                key = (hit["session_id"], hit["name"], hit["form"], location)
                if key not in seen:
                    seen.add(key)
                    hits.append({**hit, "location": location})

        scan(req.pretty_url.encode(errors="replace"), "url")
        for _, value in req.headers.fields:
            scan(value, "header")
        scan(body[:BODY_LIMIT], "body")

        peer = flow.client_conn.peername
        _emit(
            {
                "time": _now(),
                "client_ip": peer[0] if peer else None,
                "scheme": req.scheme,
                "method": req.method,
                "host": req.pretty_host,
                "port": req.port,
                "path": req.path[:200],
                "body_bytes": body_bytes,
                "tripwire_hits": hits,
                "blocked": True,
            }
        )
        flow.response = http.Response.make(
            403, BLOCK_MESSAGE, {"Content-Type": "text/plain"}
        )

    def tls_failed_client(self, data: tls.TlsData) -> None:
        conn = data.conn
        peer = data.context.client.peername
        host = conn.sni
        port = None
        if not host and data.context.server.address:
            host, port = data.context.server.address[:2]
        elif data.context.server.address:
            port = data.context.server.address[1]
        _emit(
            {
                "time": _now(),
                "client_ip": peer[0] if peer else None,
                "scheme": "https",
                "method": None,
                "host": host,
                "port": port,
                "path": "",
                "body_bytes": 0,
                "tripwire_hits": [],
                "blocked": True,
                "tls_failed": True,
            }
        )


addons = [ConnectionLogger()]

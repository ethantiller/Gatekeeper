import secrets
from pathlib import Path

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

TOKEN_HEADER_NAME = "X-Gatekeeper-Token"
DEFAULT_TOKEN_FILE_PATH = Path.home() / ".gatekeeper" / "token"


def load_or_create_token(token_file_path: Path = DEFAULT_TOKEN_FILE_PATH) -> str:
    """Read the token from disk, generating and saving a new one on first run."""
    if token_file_path.exists():
        return token_file_path.read_text().strip()

    token_file_path.parent.mkdir(parents=True, exist_ok=True)

    new_token = secrets.token_urlsafe(32)
    token_file_path.write_text(new_token)
    token_file_path.chmod(0o600) #Only owner can read/write

    return new_token


class TokenCheckMiddleware:
    """Rejects any request whose X-Gatekeeper-Token header is missing or wrong.

    Written as plain ASGI middleware, not BaseHTTPMiddleware, so it does not
    interfere with the streaming responses of the mounted MCP server.
    """

    def __init__(self, app: ASGIApp, expected_token: str) -> None:
        self.app = app
        self.expected_token = expected_token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return

        provided_token = Headers(scope=scope).get(TOKEN_HEADER_NAME, "")

        if not self._is_valid(provided_token):
            await self._reject(scope, receive, send)
            return

        await self.app(scope, receive, send)

    def _is_valid(self, provided_token: str) -> bool:
        #compare_digest takes the same amount of time every run which is cool to stop character matching off time
        return secrets.compare_digest(
            provided_token.encode(), self.expected_token.encode()
        )

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        response = JSONResponse(
            {"detail": f"Missing or invalid {TOKEN_HEADER_NAME}"}, status_code=401
        )
        await response(scope, receive, send)

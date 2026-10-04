from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from gatekeeper import database
from gatekeeper.client import gemini_client
from gatekeeper.server import hooks
from gatekeeper.server.auth import TokenCheckMiddleware, load_or_create_token
from gatekeeper.server.mcp_tools import mcp

HOST = "127.0.0.1"
PORT = 8787


def create_app(expected_token: str) -> FastAPI:
    mcp_app = mcp.http_app(path="/")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Opened once here and shared by every request: handlers read app.state.conn and
        # app.state.gemini (None when GOOGLE_API_KEY is not set).
        app.state.conn = database.connect()
        app.state.gemini = gemini_client.new_client()
        try:
            # The MCP app has its own startup and shutdown code, so FastAPI has to run it.
            async with mcp_app.lifespan(app):
                yield
        finally:
            if app.state.gemini is not None:
                await gemini_client.close_client(app.state.gemini)
            app.state.conn.close()

    app = FastAPI(lifespan=lifespan)

    app.add_middleware(TokenCheckMiddleware, expected_token=expected_token)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(hooks.router)
    app.mount("/mcp", mcp_app)

    return app


def run() -> None:
    expected_token = load_or_create_token()
    app = create_app(expected_token)

    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    run()

import uvicorn
from fastapi import FastAPI

from gatekeeper.server import hook_routes
from gatekeeper.server.auth import TokenCheckMiddleware, load_or_create_token
from gatekeeper.server.mcp_tools import mcp

HOST = "127.0.0.1"
PORT = 8787


def create_app(expected_token: str) -> FastAPI:
    mcp_app = mcp.http_app(path="/")

    # The MCP app has its own startup and shutdown code, so FastAPI has to run it.
    app = FastAPI(lifespan=mcp_app.lifespan)

    app.add_middleware(TokenCheckMiddleware, expected_token=expected_token)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(hook_routes.router)
    app.mount("/mcp", mcp_app)

    return app


def run() -> None:
    expected_token = load_or_create_token()
    app = create_app(expected_token)

    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    run()

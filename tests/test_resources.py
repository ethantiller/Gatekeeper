"""The server lifespan opens the database and Gemini client once and closes them."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gatekeeper.client import gemini_client
from gatekeeper.server.main import create_app
from gatekeeper.server.types import RiskLevel


class FakeGeminiClient:
    """Stands in for genai.Client and records whether it was closed."""

    def __init__(self) -> None:
        self.closed = False
        self.calls = 0
        self.aio = self
        self.models = self

    async def generate_content(self, **_: object) -> object:
        self.calls += 1
        text = '{"risk":"low","score":0.1,"reasoning":"ok","model":"m","latency_ms":0,"error":null}'
        return type("Response", (), {"text": text})()

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GATEKEEPER_DB", str(tmp_path / "db.sqlite"))
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)


def test_lifespan_opens_and_closes_the_database() -> None:
    app = create_app("token")
    with TestClient(app, headers={"X-Gatekeeper-Token": "token"}) as client:
        assert client.get("/health").json() == {"status": "ok"}
        conn = app.state.conn
        conn.execute("SELECT 1")
        assert app.state.gemini is None
    with pytest.raises(Exception, match="closed"):
        conn.execute("SELECT 1")


def test_lifespan_creates_and_closes_the_gemini_client(monkeypatch) -> None:
    fake = FakeGeminiClient()
    monkeypatch.setattr(gemini_client, "new_client", lambda: fake)
    app = create_app("token")
    with TestClient(app, headers={"X-Gatekeeper-Token": "token"}):
        assert app.state.gemini is fake and not fake.closed
    assert fake.closed


@pytest.mark.asyncio
async def test_a_shared_client_is_used_and_not_closed_by_the_call() -> None:
    fake = FakeGeminiClient()
    result = await gemini_client.rate_action_risk("ctx", client=fake)
    assert result.risk == RiskLevel.LOW and result.error is None
    assert fake.calls == 1 and not fake.closed


@pytest.mark.asyncio
async def test_without_a_key_or_client_the_judge_reports_an_error() -> None:
    assert (await gemini_client.rate_action_risk("ctx")).error is not None

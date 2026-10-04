"""Session start and prompt hooks through the real app and a temporary database."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gatekeeper.server.auth import TOKEN_HEADER_NAME
from gatekeeper.server.main import create_app

TOKEN = "test-token"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("GATEKEEPER_DB", str(tmp_path / "gatekeeper.db"))
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with TestClient(create_app(TOKEN), headers={TOKEN_HEADER_NAME: TOKEN}) as test_client:
        yield test_client


def start(client: TestClient, session_id: str = "s1", source: str = "startup", agent: str = "claude"):
    body = {"session_id": session_id, "cwd": str(Path.cwd()), "source": source}
    return client.post(f"/hooks/{agent}/session-start", json=body)


def send_prompt(client: TestClient, session_id: str = "s1", agent: str = "claude"):
    body = {"session_id": session_id, "cwd": str(Path.cwd()), "prompt": "hello"}
    return client.post(f"/hooks/{agent}/prompt", json=body)


def session_row(client: TestClient, session_id: str = "s1"):
    return client.app.state.conn.execute(
        "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()


@pytest.mark.parametrize("source", ["startup", "resume", "compact", "clear"])
def test_session_start_handles_every_source(client: TestClient, source: str) -> None:
    response = start(client, source=source)

    assert response.status_code == 200
    assert response.json()["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert session_row(client)["repo_root"] != ""


def test_tripwire_seed_is_random_and_never_in_the_reply(client: TestClient) -> None:
    reply = start(client, "s1")
    start(client, "s2")

    seed = session_row(client, "s1")["tripwire_seed"]
    assert seed not in ("", "s1")
    assert seed != session_row(client, "s2")["tripwire_seed"]
    assert seed not in reply.text


def test_resume_keeps_counter_and_seed(client: TestClient) -> None:
    start(client)
    seed = session_row(client)["tripwire_seed"]
    send_prompt(client)

    start(client, source="resume")

    assert session_row(client)["tripwire_seed"] == seed
    assert session_row(client)["action_counter"] == 1


def test_source_follows_the_client(client: TestClient) -> None:
    start(client, "a", agent="claude")
    start(client, "b", agent="codex")

    assert session_row(client, "a")["source"] == "claude_hook"
    assert session_row(client, "b")["source"] == "codex_hook"


def test_unknown_client_is_rejected(client: TestClient) -> None:
    assert start(client, agent="vim").status_code == 422


def test_prompt_is_counted_and_saved(client: TestClient) -> None:
    start(client)

    send_prompt(client)

    assert session_row(client)["action_counter"] == 1
    prompt = client.app.state.conn.execute("SELECT text, answers_question FROM prompts").fetchone()
    assert (prompt["text"], prompt["answers_question"]) == ("hello", None)


def test_prompt_for_unknown_session_creates_it(client: TestClient) -> None:
    send_prompt(client, "ghost", agent="codex")

    row = session_row(client, "ghost")
    assert (row["action_counter"], row["source"]) == (1, "codex_hook")


def test_prompt_answers_the_pending_question(client: TestClient) -> None:
    start(client)
    client.app.state.conn.execute(
        "UPDATE sessions SET pending_useless_question = 'why?' WHERE session_id = 's1'"
    )

    send_prompt(client)

    conn = client.app.state.conn
    assert conn.execute("SELECT answers_question FROM prompts").fetchone()[0] == "why?"
    assert session_row(client)["pending_useless_question"] is None

"""Runner setup and cleanup, the cached Docker client and the reaper.

None of these need Docker: the Docker objects are small fakes.
"""

import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from gatekeeper.sandbox import environment, runner
from gatekeeper.sandbox.environment import SandboxEnvironmentError
from gatekeeper.sandbox.runner import (
    _list_repo_files,
    _read_settled_log,
    _release,
    _RunResources,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_list_repo_files_skips_ignored(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "tracked.txt").write_text("1")
    (tmp_path / ".gitignore").write_text("ignored.txt\n")
    _git(tmp_path, "add", "tracked.txt", ".gitignore")
    (tmp_path / "untracked.txt").write_text("2")
    (tmp_path / "ignored.txt").write_text("3")

    assert sorted(_list_repo_files(tmp_path)) == [".gitignore", "tracked.txt", "untracked.txt"]


def test_repo_copy_archive_is_a_rewound_temp_file(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.txt").write_text("hello")
    archive_file = runner._build_repo_copy_archive(tmp_path, ["pkg/a.txt"])
    with archive_file, tarfile.open(fileobj=archive_file) as archive:
        assert archive.getnames() == ["workspace/pkg", "workspace/pkg/a.txt"]


def test_settled_log_skips_the_wait_when_nothing_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        runner, "read_connection_log", lambda *args, **kwargs: calls.append(1) or [{"host": "a"}]
    )
    assert _read_settled_log(0.0, "10.0.0.2", "openat(...)", []) == [{"host": "a"}]
    assert len(calls) == 1


def test_settled_log_picks_up_late_records(monkeypatch: pytest.MonkeyPatch) -> None:
    reads = [[{"host": "a"}], [{"host": "a"}, {"host": "late"}], [{"host": "a"}, {"host": "late"}]]
    monkeypatch.setattr(runner, "read_connection_log", lambda *args, **kwargs: reads.pop(0))
    monkeypatch.setattr(runner, "LOGGER_SETTLE_POLL_SECONDS", 0)
    records = _read_settled_log(0.0, "10.0.0.2", "connect(3<TCP:[...]>", [])
    assert [record["host"] for record in records] == ["a", "late"]


def test_dead_logger_gives_a_note_not_an_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*args: object, **kwargs: object) -> list[dict]:
        raise SandboxEnvironmentError("The connection logger is not running.")

    monkeypatch.setattr(runner, "read_connection_log", broken)
    warnings: list[str] = []
    assert _read_settled_log(0.0, "10.0.0.2", "connect(", warnings) == []
    assert "could not be read" in warnings[0]


def test_release_runs_every_step_even_when_unregistering_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    removed = []

    def failing_unregister(label: str) -> None:
        raise SandboxEnvironmentError("logger gone")

    class FakeContainer:
        def remove(self, force: bool) -> None:
            removed.append(force)

    class FakeFile:
        closed = False

        def close(self) -> None:
            self.closed = True

    temp_file = FakeFile()
    monkeypatch.setattr(runner, "unregister_tripwires", failing_unregister)
    resources = _RunResources(container=FakeContainer(), archives=[b"bytes", temp_file])  # type: ignore[arg-type]
    with pytest.raises(SandboxEnvironmentError):
        _release(resources, "label")
    assert removed == [True]
    assert temp_file.closed


def test_docker_client_is_created_once_and_pinged_rarely(monkeypatch: pytest.MonkeyPatch) -> None:
    pings = []

    class FakeClient:
        def ping(self) -> None:
            pings.append(1)

    created = []
    monkeypatch.setattr(environment, "_cached_client", None)
    monkeypatch.setattr(environment.docker, "from_env", lambda: created.append(1) or FakeClient())

    first = environment.get_docker_client()
    for _ in range(5):
        assert environment.get_docker_client() is first
    assert len(created) == 1
    assert len(pings) == 1

    monkeypatch.setattr(environment, "_last_ping", time.monotonic() - 2 * environment.PING_INTERVAL_SECONDS)
    environment.get_docker_client()
    assert len(pings) == 2


def test_reaper_removes_only_old_labelled_containers() -> None:
    class FakeContainer:
        def __init__(self, started_at: float | None) -> None:
            self.labels = {} if started_at is None else {environment.SANDBOX_STARTED_LABEL: str(started_at)}
            self.removed = False

        def remove(self, force: bool) -> None:
            self.removed = True

    now = time.time()
    old, recent, unlabeled_time = FakeContainer(now - 3600), FakeContainer(now), FakeContainer(None)

    class FakeContainers:
        def list(self, all: bool, filters: dict) -> list[FakeContainer]:
            assert filters == {"label": f"{environment.SANDBOX_CONTAINER_LABEL}=true"}
            return [old, recent, unlabeled_time]

    class FakeClient:
        containers = FakeContainers()

    environment._remove_stale_sandboxes(FakeClient())  # type: ignore[arg-type]
    assert (old.removed, recent.removed, unlabeled_time.removed) == (True, False, True)


def test_new_sandbox_containers_carry_the_reaper_labels() -> None:
    labels = environment.sandbox_container_labels()
    assert labels[environment.SANDBOX_CONTAINER_LABEL] == "true"
    assert float(labels[environment.SANDBOX_STARTED_LABEL]) <= time.time()

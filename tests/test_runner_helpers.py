"""Pure helpers in the sandbox runner: redaction, host path warnings, working folder, copying."""

import os
from pathlib import Path

import pytest
from docker.errors import APIError, NotFound

from gatekeeper.sandbox import runner
from gatekeeper.sandbox.environment import SandboxEnvironmentError
from gatekeeper.sandbox.runner import (
    OUTPUT_TAIL_BYTES,
    WORKSPACE,
    _build_repo_copy_archive,
    _container_workdir,
    _evidence_problems,
    _host_path_warnings,
    _modified_files,
    _read_strace_text,
    _remove_container,
    _tail,
)
from gatekeeper.sandbox.tripwires import generate_tripwire_values

SEED = "test-seed"


def test_tail_redacts_fake_secrets_even_when_cut_by_the_tail() -> None:
    values = generate_tripwire_values(SEED)
    secret = values["OPENAI_API_KEY"]
    output = ("x" * OUTPUT_TAIL_BYTES + f"OPENAI_API_KEY={secret}\n").encode()

    tail = _tail(output, SEED)

    assert secret not in tail
    assert "[tripwire OPENAI_API_KEY]" in tail
    assert len(tail) <= OUTPUT_TAIL_BYTES


def test_workdir_follows_the_agents_folder_inside_the_repo(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    warnings: list[str] = []

    assert _container_workdir(str(tmp_path / "frontend"), tmp_path, warnings) == f"{WORKSPACE}/frontend"
    assert _container_workdir(str(tmp_path), tmp_path, warnings) == WORKSPACE
    assert warnings == []


def test_workdir_outside_the_repo_falls_back_with_a_warning(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    warnings: list[str] = []

    assert _container_workdir(str(tmp_path), repo, warnings) == WORKSPACE
    assert len(warnings) == 1


def test_warns_about_ignored_and_outside_paths_but_not_copied_ones(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x")
    (repo / "node_modules").mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()

    warnings = _host_path_warnings(
        f"rm -rf src node_modules {outside}", repo, repo, repo_file_paths=["src/a.py"]
    )

    assert len(warnings) == 2
    assert any("node_modules" in warning and "gitignored" in warning for warning in warnings)
    assert any("outside the repo" in warning for warning in warnings)
    assert not any(warning.startswith("src ") for warning in warnings)


def test_unparseable_command_gives_no_path_warnings(tmp_path: Path) -> None:
    assert _host_path_warnings("echo 'unclosed", tmp_path, tmp_path, []) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_file_is_a_sandbox_error_not_a_crash(tmp_path: Path) -> None:
    locked = tmp_path / "locked.txt"
    locked.write_text("secret")
    locked.chmod(0)

    try:
        with pytest.raises(SandboxEnvironmentError):
            _build_repo_copy_archive(tmp_path, ["locked.txt"])
    finally:
        locked.chmod(0o600)


class _Result:
    def __init__(self, exit_code: int = 0, output: bytes = b"") -> None:
        self.exit_code = exit_code
        self.output = output


class _FakeContainer:
    """Answers exec_run from a table of command prefix -> result."""

    def __init__(self, answers: dict[str, _Result]) -> None:
        self.answers = answers
        self.commands: list[list[str]] = []

    def exec_run(self, command: list[str], **kwargs: object) -> _Result:
        self.commands.append(command)
        for prefix, result in self.answers.items():
            if " ".join(command).startswith(prefix):
                return result
        return _Result(1)


def test_untouched_trace_gives_no_evidence_problems() -> None:
    container = _FakeContainer({
        "cat /tmp/gk-strace-inode": _Result(output=b"42\n"),
        "stat -c %i": _Result(output=b"42\n"),
        "grep -q": _Result(1),
    })

    assert _evidence_problems(container) == []  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ({"cat /tmp/gk-strace-inode": _Result(1)}, "starting state"),
        ({"cat /tmp/gk-strace-inode": _Result(output=b"42"), "stat -c %i": _Result(1)}, "deleted"),
        (
            {"cat /tmp/gk-strace-inode": _Result(output=b"42"), "stat -c %i": _Result(output=b"43")},
            "replaced",
        ),
        (
            {
                "cat /tmp/gk-strace-inode": _Result(output=b"42"),
                "stat -c %i": _Result(output=b"42"),
                "grep -q": _Result(0),
            },
            "overwrote",
        ),
    ],
)
def test_tampering_with_the_trace_is_noticed(answers: dict[str, _Result], expected: str) -> None:
    problems = _evidence_problems(_FakeContainer(answers))  # type: ignore[arg-type]

    assert len(problems) == 1
    assert expected in problems[0]


def test_trace_text_is_capped_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "STRACE_TEXT_MAX_BYTES", 10)
    full = _FakeContainer({"sh -c": _Result(output=b"0123456789")})
    short = _FakeContainer({"sh -c": _Result(output=b"0123")})

    assert _read_strace_text(full) == ("0123456789", True)  # type: ignore[arg-type]
    assert _read_strace_text(short) == ("0123", False)  # type: ignore[arg-type]


def test_tripwire_lines_are_read_before_the_capped_filter() -> None:
    container = _FakeContainer({"sh -c": _Result()})

    _read_strace_text(container)  # type: ignore[arg-type]

    script = container.commands[0][-1]
    assert script.index("</workspace/.env>") < script.index("head -c")


def test_modified_files_use_change_time_not_modification_time() -> None:
    container = _FakeContainer({"find": _Result(output=b"/workspace/a\n/workspace/new\n")})

    modified = _modified_files(container, {"/workspace/new"}, "1700000000.5")  # type: ignore[arg-type]

    assert modified == ["/workspace/a"]
    assert "-newerct" in container.commands[0]
    assert "@1700000000.5" in container.commands[0]
    assert "-newer" not in container.commands[0]


def test_failure_to_remove_the_container_is_a_sandbox_error() -> None:
    class StuckContainer:
        def remove(self, force: bool) -> None:
            raise APIError("daemon busy")

    with pytest.raises(SandboxEnvironmentError):
        _remove_container(StuckContainer())  # type: ignore[arg-type]


def test_missing_container_is_fine_to_remove() -> None:
    class GoneContainer:
        def remove(self, force: bool) -> None:
            raise NotFound("gone")

    _remove_container(GoneContainer())  # type: ignore[arg-type]


def test_dev_null_in_a_command_is_not_a_host_path_warning(tmp_path: Path) -> None:
    assert _host_path_warnings("cat x > /dev/null", tmp_path, tmp_path, []) == []


def test_tracer_exit_code_must_match_the_command_exit_code() -> None:
    from gatekeeper.sandbox.runner import _CommandResult

    assert _CommandResult(0, False, False, False).tracer_stopped is False
    assert _CommandResult(0, False, False, False, tracer_stopped=True).tracer_stopped

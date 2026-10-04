"""Pure helpers in the sandbox runner: redaction, host path warnings, working folder, copying."""

import os
from pathlib import Path

import pytest

from gatekeeper.sandbox.environment import SandboxEnvironmentError
from gatekeeper.sandbox.runner import (
    OUTPUT_TAIL_BYTES,
    WORKSPACE,
    _build_repo_copy_archive,
    _container_workdir,
    _host_path_warnings,
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

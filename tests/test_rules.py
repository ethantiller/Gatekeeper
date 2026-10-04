from pathlib import Path

import pytest

from gatekeeper.pipeline.rules import DEFAULT_RULES_PATH, load_rules


def test_loads_default_rules_when_repository_has_no_override(tmp_path: Path) -> None:
    rules = load_rules(tmp_path)

    assert DEFAULT_RULES_PATH.is_file()
    assert rules["version"] == 1
    assert "git status" in rules["safe_commands"]
    assert "github.com" in rules["allowed_hosts"]
    assert "**/.env" in rules["protected_files"]
    assert rules["never_allowed"]


def test_repository_lists_append_and_scalar_values_replace(tmp_path: Path) -> None:
    (tmp_path / ".gatekeeper.yaml").write_text(
        """\
version: 2
failure_mode: allow_all
approval_timeout_seconds: 15
safe_commands:
  - repo-command
allowed_hosts:
  - repo.example.test
tags:
  network:
    programs:
      - repo-network-command
  repo_tag:
    programs:
      - repo-program
""",
        encoding="utf-8",
    )

    rules = load_rules(tmp_path)

    assert rules["version"] == 2
    assert rules["failure_mode"] == "allow_all"
    assert rules["approval_timeout_seconds"] == 15
    assert rules["safe_commands"][-1] == "repo-command"
    assert rules["allowed_hosts"][-1] == "repo.example.test"
    assert "curl" in rules["tags"]["network"]["programs"]
    assert rules["tags"]["network"]["programs"][-1] == "repo-network-command"
    assert rules["tags"]["repo_tag"]["programs"] == ["repo-program"]


def test_loads_fresh_defaults_for_each_repository(tmp_path: Path) -> None:
    first_load = load_rules(tmp_path)
    first_load["safe_commands"].append("local-only")

    second_load = load_rules(tmp_path)

    assert "local-only" not in second_load["safe_commands"]


def test_rejects_non_mapping_repository_rules(tmp_path: Path) -> None:
    (tmp_path / ".gatekeeper.yaml").write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(TypeError, match="YAML mapping"):
        load_rules(tmp_path)

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "rules.yaml"
REPOSITORY_RULES_NAME = ".gatekeeper.yaml"


def load_rules(repo_path: str | Path | None = None) -> dict[str, Any]:
    """Load default rules and overlay a repository's optional rule file."""
    defaults = _read_rules(DEFAULT_RULES_PATH)
    repository = Path.cwd() if repo_path is None else Path(repo_path)
    override_path = repository / REPOSITORY_RULES_NAME

    if not override_path.exists():
        return defaults

    return _merge(defaults, _read_rules(override_path))


def _read_rules(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as rules_file:
        rules = yaml.safe_load(rules_file)

    if rules is None:
        return {}
    if not isinstance(rules, dict):
        raise TypeError(f"Rules file must contain a YAML mapping: {path}")
    return rules


def _merge(defaults: Any, overrides: Any) -> Any:
    if isinstance(defaults, dict) and isinstance(overrides, dict):
        merged = deepcopy(defaults)
        for key, value in overrides.items():
            if key in merged:
                merged[key] = _merge(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged

    if isinstance(defaults, list) and isinstance(overrides, list):
        return deepcopy(defaults) + deepcopy(overrides)

    return deepcopy(overrides)

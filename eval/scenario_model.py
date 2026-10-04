"""The scenario file format, and loading and checking every scenario before a run starts."""

import re
from pathlib import Path, PurePosixPath
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

EVAL_DIR = Path(__file__).resolve().parent
SCENARIOS_DIR = EVAL_DIR / "scenarios"
FIXTURE_REPOS_DIR = EVAL_DIR / "fixture_repos"

# Written into prompts, fixture files and canary files. The runner swaps it for the live,
# run-specific canary address, so no scenario can name a real host.
CANARY_PLACEHOLDER = "__CANARY_URL__"

ATTACK_CATEGORIES = (
    "prompt_injection",
    "npm_postinstall",
    "curl_pipe_sh",
    "env_exfil",
    "ci_tamper",
)
BENIGN_CATEGORY = "benign"

# Hosts a scenario may name directly. Everything else has to go through the placeholder.
LOCAL_HOSTS = {"127.0.0.1", "localhost"}
URL_PATTERN = re.compile(r"""(?:https?|ftp)://([^/\s"'`)>\]:]+)""", re.IGNORECASE)
FAKE_MARKER = "FAKE"  # every secret in a scenario or fixture must contain this
MAX_FIXTURE_FILE_BYTES = 1_000_000


class ScenarioError(Exception):
    """A scenario file or fixture repo is invalid. The message says which and why."""


class SuccessCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["canary_request", "file_changed", "file_exists"]
    value: str = Field(
        min_length=1,
        description="canary_request: the request path (starts with /). "
        "file_changed, file_exists: a path relative to the repo",
    )


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    kind: Literal["attack", "benign"]
    category: str
    repo: str = Field(description="A folder under eval/fixture_repos/")
    prompt: str = Field(min_length=1)
    success_check: SuccessCheck | None = None
    timeout_seconds: int = Field(default=300, gt=0, le=1800)
    description: str = ""
    max_turns: int | None = Field(default=None, gt=0, le=200)
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Extra fake environment variables for the agent. Values must contain FAKE.",
    )
    files: dict[str, str] = Field(
        default_factory=dict,
        description="Files written over the fixture repo before the first commit",
    )
    after_commit_files: dict[str, str] = Field(
        default_factory=dict,
        description="Files written after the first commit: untracked, or modifying a tracked file",
    )
    canary_files: dict[str, str] = Field(
        default_factory=dict,
        description="Pages the canary serves for this run, keyed by path (starts with /)",
    )

    @model_validator(mode="after")
    def check_consistency(self) -> "Scenario":
        if self.kind == "attack":
            if self.category not in ATTACK_CATEGORIES:
                raise ValueError(
                    f"category: an attack's category must be one of {', '.join(ATTACK_CATEGORIES)}"
                )
            if self.success_check is None:
                raise ValueError("success_check: an attack needs one")
        else:
            if self.category != BENIGN_CATEGORY:
                raise ValueError(f"category: a benign scenario's category must be {BENIGN_CATEGORY}")
            if self.success_check is not None:
                raise ValueError("success_check: only attacks have one")

        check = self.success_check
        if check is not None:
            if check.type == "canary_request":
                if not check.value.startswith("/"):
                    raise ValueError("success_check.value: a canary path must start with /")
                if check.value in self.canary_files:
                    raise ValueError(
                        "success_check.value: must not be a page the canary serves, "
                        "or fetching the page would count as the attack"
                    )
            else:
                _check_relative_path(check.value, "success_check.value")

        for field_name in ("files", "after_commit_files"):
            for path in getattr(self, field_name):
                _check_relative_path(path, f"{field_name}.{path}")
        for path in self.canary_files:
            if not path.startswith("/") or ".." in path.split("/"):
                raise ValueError(f"canary_files.{path}: must start with / and contain no ..")
        for name, value in self.env.items():
            if FAKE_MARKER not in value:
                raise ValueError(f"env.{name}: secrets must be obviously fake (contain {FAKE_MARKER})")
        return self


def _check_relative_path(path: str, where: str) -> None:
    posix = PurePosixPath(path)
    if posix.is_absolute() or ".." in posix.parts or not path:
        raise ValueError(f"{where}: must be a relative path inside the repo, got {path!r}")


def foreign_urls(text: str) -> list[str]:
    """Every URL in the text whose host is not local. The canary placeholder never matches."""
    return [
        match.group(0)
        for match in URL_PATTERN.finditer(text)
        if match.group(1).lower() not in LOCAL_HOSTS
    ]


def dotted(relative_path: str) -> str:
    """Fixture folders can't hold files such as .env (the repo's .gitignore excludes them).

    A path part that starts with `dot_` is copied with a leading dot instead: dot_env is .env.
    """
    parts = [("." + part[4:]) if part.startswith("dot_") else part for part in relative_path.split("/")]
    return "/".join(parts)


def fixture_files(repo: str) -> dict[str, Path]:
    """Every file in a fixture repo, keyed by the path it will have in the run folder."""
    root = FIXTURE_REPOS_DIR / repo
    return {
        dotted(path.relative_to(root).as_posix()): path
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != ".gitkeep"
    }


def _read_text(path: Path) -> str | None:
    """File text, or None for binary files, which are not scanned."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def check_fixture_repo(repo: str) -> list[str]:
    """Problems with one fixture repo: missing, too large, a real URL, or a non-fake secret."""
    root = FIXTURE_REPOS_DIR / repo
    if not root.is_dir():
        return [f"fixture repo {repo!r} does not exist under {FIXTURE_REPOS_DIR}"]
    problems = []
    files = fixture_files(repo)
    if not files:
        problems.append(f"fixture repo {repo!r} is empty")
    for relative_path, source in files.items():
        if source.stat().st_size > MAX_FIXTURE_FILE_BYTES:
            problems.append(f"{repo}/{relative_path}: larger than {MAX_FIXTURE_FILE_BYTES} bytes")
            continue
        text = _read_text(source)
        if text is None:
            continue
        for url in foreign_urls(text):
            problems.append(f"{repo}/{relative_path}: names a non-local host ({url}); use {CANARY_PLACEHOLDER}")
        if relative_path.rsplit("/", 1)[-1].startswith(".env") and FAKE_MARKER not in text:
            problems.append(f"{repo}/{relative_path}: an env file must contain {FAKE_MARKER} values")
    return problems


def load_scenario(path: Path) -> Scenario:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ScenarioError(f"{path.name}: not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise ScenarioError(f"{path.name}: expected a mapping at the top level")
    try:
        scenario = Scenario.model_validate(raw)
    except ValidationError as error:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or 'file'}: {item['msg'].removeprefix('Value error, ')}"
            for item in error.errors()
        )
        raise ScenarioError(f"{path.name}: {details}") from error
    _check_against_fixture(path, scenario)
    return scenario


def _check_against_fixture(path: Path, scenario: Scenario) -> None:
    problems = []
    if not (FIXTURE_REPOS_DIR / scenario.repo).is_dir():
        problems.append(f"repo: no fixture repo named {scenario.repo!r} under eval/fixture_repos/")
    else:
        existing = set(fixture_files(scenario.repo)) | set(scenario.files)
        check = scenario.success_check
        if check is not None and check.type == "file_changed" and check.value not in existing:
            problems.append(f"success_check.value: {check.value} is not in the repo, so it cannot change")
        if check is not None and check.type == "file_exists" and check.value in existing | set(
            scenario.after_commit_files
        ):
            problems.append(f"success_check.value: {check.value} already exists before the run")
    texts = {"prompt": scenario.prompt}
    texts.update({f"files.{name}": text for name, text in scenario.files.items()})
    texts.update({f"after_commit_files.{name}": text for name, text in scenario.after_commit_files.items()})
    texts.update({f"canary_files.{name}": text for name, text in scenario.canary_files.items()})
    for where, text in texts.items():
        for url in foreign_urls(text):
            problems.append(f"{where}: names a non-local host ({url}); use {CANARY_PLACEHOLDER}")
    if problems:
        raise ScenarioError(f"{path.name}: " + "; ".join(problems))


def load_scenarios(directory: Path = SCENARIOS_DIR) -> list[Scenario]:
    """Load every scenario, or raise one ScenarioError that lists every problem found."""
    scenarios: list[Scenario] = []
    problems: list[str] = []
    seen: dict[str, Path] = {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            scenario = load_scenario(path)
        except ScenarioError as error:
            problems.append(str(error))
            continue
        if scenario.id in seen:
            problems.append(f"{path.name}: id {scenario.id!r} is already used by {seen[scenario.id].name}")
            continue
        seen[scenario.id] = path
        scenarios.append(scenario)
    for repo in sorted({scenario.repo for scenario in scenarios}):
        problems.extend(check_fixture_repo(repo))
    if problems:
        raise ScenarioError("Invalid scenarios:\n  - " + "\n  - ".join(problems))
    if not scenarios:
        raise ScenarioError(f"No scenarios found in {directory}")
    return scenarios

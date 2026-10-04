"""`~/.gatekeeper`: the folder, token, database, user rules and API key file."""

import os
import shutil
import stat
from pathlib import Path

from dotenv import dotenv_values, set_key

from gatekeeper import database
from gatekeeper.pipeline.rules import DEFAULT_RULES_PATH
from gatekeeper.server.auth import load_or_create_token
from gatekeeper.setup import paths

HOME_MODE = 0o700
SECRET_FILE_MODE = 0o600
API_KEY_NAME = "GOOGLE_API_KEY"
MODEL_NAME = "GEMINI_MODEL"


def create_home() -> list[str]:
    """Create or repair the home folder and everything in it; return what was created or fixed."""
    changes: list[str] = []
    home = paths.gatekeeper_home()
    if not home.exists():
        changes.append(f"created {home}")
    home.mkdir(mode=HOME_MODE, parents=True, exist_ok=True)
    if stat.S_IMODE(home.stat().st_mode) != HOME_MODE:
        home.chmod(HOME_MODE)
        changes.append(f"set {home} to mode 0700")

    token = paths.token_path()
    if not token.exists():
        changes.append("created the token")
    load_or_create_token(token)
    if stat.S_IMODE(token.stat().st_mode) != SECRET_FILE_MODE:
        token.chmod(SECRET_FILE_MODE)
        changes.append("set the token to mode 0600")

    saved_changes = home / "saved_changes"
    if not saved_changes.exists():
        changes.append("created saved_changes/")
    saved_changes.mkdir(exist_ok=True)

    rules = paths.rules_path()
    if not rules.exists():
        shutil.copyfile(DEFAULT_RULES_PATH, rules)  # an existing user file is never overwritten
        changes.append("copied the default rules.yaml")

    database_existed = _database_path().exists()
    database.connect().close()
    if not database_existed:
        changes.append("created the database")
    return changes


def _database_path() -> Path:
    return Path(os.environ.get("GATEKEEPER_DB", paths.gatekeeper_home() / "gatekeeper.db"))


def read_token() -> str:
    return paths.token_path().read_text().strip()


def saved_api_key() -> str | None:
    """The key in `~/.gatekeeper/.env`, if any."""
    return dotenv_values(paths.env_path()).get(API_KEY_NAME) or None


def save_api_key(api_key: str) -> bool:
    """Write the key (and `GEMINI_MODEL` if set) to the server's `.env`; True if it changed."""
    env_file = paths.env_path()
    before = dotenv_values(env_file)
    env_file.touch(mode=SECRET_FILE_MODE, exist_ok=True)
    env_file.chmod(SECRET_FILE_MODE)
    set_key(env_file, API_KEY_NAME, api_key, quote_mode="never")
    model = os.environ.get(MODEL_NAME)
    if model:
        set_key(env_file, MODEL_NAME, model, quote_mode="never")
    return dotenv_values(env_file) != before

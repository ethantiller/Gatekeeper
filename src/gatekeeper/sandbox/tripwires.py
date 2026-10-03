"""Per-session fake secret values and the files that plant them in a sandbox container."""

import hashlib
import hmac
import io
import json
import string
import tarfile
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "docker" / "tripwire_templates"

SANDBOX_UID = 1000
SANDBOX_GID = 1000

WORKSPACE_ENV_PATH = "/workspace/.env"
AWS_CREDENTIALS_PATH = "/home/sandbox/.aws/credentials"

_ALNUM = string.ascii_letters + string.digits
_UPPER_DIGITS = string.ascii_uppercase + string.digits
_B64_CHARS = _ALNUM + "+/"
_HEX = "0123456789abcdef"

# placeholder name -> (prefix, alphabet, length of the random part)
_FORMATS = {
    "AWS_ACCESS_KEY_ID": ("AKIA", _UPPER_DIGITS, 16),
    "AWS_SECRET_ACCESS_KEY": ("", _B64_CHARS, 40),
    "OPENAI_API_KEY": ("sk-proj-", _ALNUM, 48),
    "STRIPE_SECRET_KEY": ("sk_live_", _ALNUM, 24),
    "JWT_SECRET": ("", _HEX, 64),
    "DATABASE_PASSWORD": ("", _ALNUM, 24),
}


def _stream(seed: str, name: str, length: int) -> bytes:
    """Deterministic bytes: HMAC-SHA256(seed, name), extended with a counter if more is needed."""
    key = seed.encode()
    out = hmac.new(key, name.encode(), hashlib.sha256).digest()
    counter = 1
    while len(out) < length:
        out += hmac.new(key, f"{name}:{counter}".encode(), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def generate_tripwire_values(seed: str) -> dict[str, str]:
    """Placeholder name -> realistic-looking fake value. Same seed, same values."""
    values = {}
    for name, (prefix, alphabet, length) in _FORMATS.items():
        raw = _stream(seed, name, length)
        values[name] = prefix + "".join(alphabet[b % len(alphabet)] for b in raw)
    return values


def _render(template_name: str, values: dict[str, str]) -> bytes:
    text = (TEMPLATE_DIR / template_name).read_text()
    for name, value in values.items():
        text = text.replace("{{" + name + "}}", value)
    return text.encode()


def render_tripwire_files(seed: str, skip_workspace_env: bool = False) -> dict[str, bytes]:
    """Container path -> file contents."""
    values = generate_tripwire_values(seed)
    files = {}
    if not skip_workspace_env:
        files[WORKSPACE_ENV_PATH] = _render("env.template", values)
    files[AWS_CREDENTIALS_PATH] = _render("aws_credentials.template", values)
    return files


def _dir_entry(name: str, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.uid = info.gid = SANDBOX_UID
    return info


def build_tripwire_archive(seed: str, skip_workspace_env: bool = False) -> bytes:
    """Tar archive for container.put_archive("/", data)."""
    files = render_tripwire_files(seed, skip_workspace_env)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        dirs = []
        if WORKSPACE_ENV_PATH in files:
            dirs.append(("workspace", 0o755))
        dirs += [("home/sandbox", 0o755), ("home/sandbox/.aws", 0o700)]
        for name, mode in dirs:
            tar.addfile(_dir_entry(name, mode))
        for path, content in files.items():
            info = tarfile.TarInfo(path.lstrip("/"))
            info.size = len(content)
            info.mode = 0o600
            info.uid = info.gid = SANDBOX_UID
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def registry_entry(session_id: str, seed: str) -> bytes:
    """JSON for the connection logger's /registry directory."""
    return json.dumps(
        {"session_id": session_id, "values": generate_tripwire_values(seed)}
    ).encode()

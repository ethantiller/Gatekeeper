"""Pure-Python tripwire matching helpers (no mitmproxy imports, so host tests can import this)."""

import base64
import json
import os
from pathlib import Path
from urllib.parse import quote, quote_plus

# Leading characters of a base64 string that depend on bytes before the value.
_B64_LEAD_DROP = {0: 0, 1: 2, 2: 3}


def _b64_variants(raw: bytes, urlsafe: bool) -> list[bytes]:
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out = []
    for offset in range(3):
        encoded = encode(b"\x00" * offset + raw).rstrip(b"=")
        encoded = encoded[_B64_LEAD_DROP[offset]:]
        if (offset + len(raw)) % 3 != 0:
            encoded = encoded[:-1]  # last char mixes in following bytes
        out.append(encoded)
    return out


def build_variants(value: str) -> dict[str, list[bytes]]:
    """Form name -> byte strings to search for."""
    raw = value.encode()
    return {
        "raw": [raw],
        "url": list(
            dict.fromkeys(
                [quote(value, safe="").encode(), quote_plus(value, safe="").encode()]
            )
        ),
        "hex": [raw.hex().encode(), raw.hex().upper().encode()],
        "base64": _b64_variants(raw, urlsafe=False),
        "base64url": _b64_variants(raw, urlsafe=True),
    }


def make_entry(session_id: str, values: dict[str, str]) -> dict:
    return {
        "session_id": session_id,
        "variants": {name: build_variants(value) for name, value in values.items()},
    }


def load_registry(directory: str | os.PathLike = "/registry") -> list[dict]:
    """Read every *.json in the directory. Unreadable files are skipped."""
    entries = []
    for path in sorted(Path(directory).glob("*.json")):
        try:
            data = json.loads(path.read_text())
            entries.append(make_entry(data["session_id"], data["values"]))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return entries


def registry_signature(directory: str | os.PathLike = "/registry") -> tuple:
    """Changes whenever a registry file is added, removed or rewritten."""
    try:
        root = Path(directory)
        files = tuple(
            (p.name, p.stat().st_mtime_ns, p.stat().st_size)
            for p in sorted(root.glob("*.json"))
        )
        return (root.stat().st_mtime_ns, files)
    except OSError:
        return ()


def find_hits(data: bytes, registry: list[dict]) -> list[dict]:
    """Return {session_id, name, form} for each tripwire found in data (first matching form)."""
    if not data or not registry:
        return []
    # Line-wrapped base64 (e.g. plain `base64`) has newlines inside the blob.
    stripped = data.replace(b"\r", b"").replace(b"\n", b"") if b"\n" in data else None
    hits = []
    for entry in registry:
        for name, forms in entry["variants"].items():
            found = False
            for form, needles in forms.items():
                for hay in (data, stripped) if form.startswith("base64") else (data,):
                    if hay is not None and any(n and n in hay for n in needles):
                        hits.append(
                            {"session_id": entry["session_id"], "name": name, "form": form}
                        )
                        found = True
                        break
                if found:
                    break
    return hits

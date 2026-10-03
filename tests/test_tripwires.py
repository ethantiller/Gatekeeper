import base64
import io
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker" / "connection_logger"))

import tripwire_match

from gatekeeper.sandbox.tripwires import (
    build_tripwire_archive,
    generate_tripwire_values,
    registry_entry,
    render_tripwire_files,
)

SEED = "seed-one"
OTHER_SEED = "seed-two"


def _registry(seed, session_id="s1"):
    return [tripwire_match.make_entry(session_id, generate_tripwire_values(seed))]


def test_deterministic_and_seed_dependent():
    assert generate_tripwire_values(SEED) == generate_tripwire_values(SEED)
    a, b = generate_tripwire_values(SEED), generate_tripwire_values(OTHER_SEED)
    assert all(a[k] != b[k] for k in a)


def test_formats():
    v = generate_tripwire_values(SEED)
    assert v["AWS_ACCESS_KEY_ID"].startswith("AKIA") and len(v["AWS_ACCESS_KEY_ID"]) == 20
    assert v["AWS_ACCESS_KEY_ID"][4:].isalnum() and v["AWS_ACCESS_KEY_ID"][4:].upper() == v["AWS_ACCESS_KEY_ID"][4:]
    assert len(v["AWS_SECRET_ACCESS_KEY"]) == 40
    assert set(v["AWS_SECRET_ACCESS_KEY"]) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    assert v["OPENAI_API_KEY"].startswith("sk-proj-") and len(v["OPENAI_API_KEY"]) == 8 + 48
    assert v["OPENAI_API_KEY"][8:].isalnum()
    assert v["STRIPE_SECRET_KEY"].startswith("sk_live_") and len(v["STRIPE_SECRET_KEY"]) == 8 + 24
    assert v["STRIPE_SECRET_KEY"][8:].isalnum()
    assert len(v["JWT_SECRET"]) == 64 and int(v["JWT_SECRET"], 16) >= 0
    assert len(v["DATABASE_PASSWORD"]) == 24 and v["DATABASE_PASSWORD"].isalnum()


def test_render_files():
    files = render_tripwire_files(SEED)
    assert set(files) == {"/workspace/.env", "/home/sandbox/.aws/credentials"}
    assert b"{{" not in files["/workspace/.env"] + files["/home/sandbox/.aws/credentials"]
    assert set(render_tripwire_files(SEED, skip_workspace_env=True)) == {
        "/home/sandbox/.aws/credentials"
    }


def test_registry_entry_contents():
    import json

    entry = json.loads(registry_entry("sess", SEED))
    assert entry["session_id"] == "sess"
    assert entry["values"] == generate_tripwire_values(SEED)


def _members(archive):
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        return {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar}


def test_archive_layout():
    members = _members(build_tripwire_archive(SEED))
    files = render_tripwire_files(SEED)
    for path, content in files.items():
        info, data = members[path.lstrip("/")]
        assert data == content
        assert info.mode == 0o600 and info.uid == 1000 and info.gid == 1000
    aws_dir = members["home/sandbox/.aws"][0]
    assert aws_dir.isdir() and aws_dir.mode == 0o700 and aws_dir.uid == 1000


def test_archive_skip_workspace_env():
    names = set(_members(build_tripwire_archive(SEED, skip_workspace_env=True)))
    assert "workspace/.env" not in names
    assert "home/sandbox/.aws/credentials" in names


def _encodings(data: bytes) -> dict[str, bytes]:
    from urllib.parse import quote, quote_plus

    text = data.decode()
    return {
        "url": quote(text, safe="").encode(),
        "url_plus": quote_plus(text).encode(),
        "hex": data.hex().encode(),
        "base64": base64.b64encode(data),
        "base64url": base64.urlsafe_b64encode(data),
    }


@pytest.mark.parametrize("path", ["/workspace/.env", "/home/sandbox/.aws/credentials"])
def test_whole_file_encodings_hit_every_value(path):
    values = generate_tripwire_values(SEED)
    content = render_tripwire_files(SEED)[path]
    expected = {name for name, value in values.items() if value.encode() in content}
    assert expected
    registry = _registry(SEED)
    for label, blob in {"raw": content, **_encodings(content)}.items():
        assert {h["name"] for h in tripwire_match.find_hits(blob, registry)} == expected, label
    other = _registry(OTHER_SEED, "s2")
    for blob in [content, *_encodings(content).values()]:
        assert tripwire_match.find_hits(blob, other) == []


@pytest.mark.parametrize("prefix_len", [0, 1, 2])
def test_base64_alignments(prefix_len):
    value = generate_tripwire_values(SEED)["AWS_SECRET_ACCESS_KEY"]
    blob = base64.b64encode(b"x" * prefix_len + value.encode() + b"tail!")
    hits = tripwire_match.find_hits(blob, _registry(SEED))
    assert [h["name"] for h in hits] == ["AWS_SECRET_ACCESS_KEY"]
    assert hits[0]["form"] == "base64"


def test_wrapped_base64_is_found():
    content = render_tripwire_files(SEED)["/workspace/.env"]
    wrapped = base64.encodebytes(content)  # newline every 76 chars
    assert tripwire_match.find_hits(wrapped, _registry(SEED))

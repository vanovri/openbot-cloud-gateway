"""Stage the encrypted migration pack into the OpenBot /data volume.

The pack (agent profiles, sidebar sections, routines, AGENTS.md bodies and
local skills) travels as a GitHub secret so it never touches a public git ref.
It is decoded into ``<data>/migration/`` before the container starts, so the
OpenBot agent inside the container can apply it with its own tools.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

MAX_PACK_BYTES = 8 * 1024 * 1024
REQUIRED_KEYS = ("agents", "sections", "routines")
DEFAULT_APPLY_MD = """# Migration pack

This folder holds `pack.json`: the agent roster, sidebar sections, routines,
AGENTS.md bodies and local skills exported from the user's laptop server.
Read it and recreate the items with your own OpenBot tools. Create only what
does not already exist; never copy local Windows paths or provider secrets.
"""


def decode_pack(encoded: str) -> dict:
    """Decode base64(gzip(json)) with strict size limits."""
    raw = encoded.strip()
    if not raw:
        raise ValueError("empty pack")
    try:
        compressed = base64.b64decode(raw, validate=True)
    except Exception as exc:  # noqa: BLE001 - report a clean error
        raise ValueError(f"pack is not valid base64: {exc}") from exc
    if len(compressed) > MAX_PACK_BYTES:
        raise ValueError("compressed pack exceeds size limit")
    try:
        payload = gzip.decompress(compressed)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"pack is not valid gzip: {exc}") from exc
    if len(payload) > MAX_PACK_BYTES:
        raise ValueError("uncompressed pack exceeds size limit")
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"pack is not valid json: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("pack root must be an object")
    missing = [key for key in REQUIRED_KEYS if key not in data]
    if missing:
        raise ValueError(f"pack missing keys: {', '.join(missing)}")
    return data


def _write_atomic(path: Path, payload: bytes) -> bool:
    """Write payload when its bytes changed. Returns True when written."""
    digest = hashlib.sha256(payload).hexdigest()
    if path.exists():
        try:
            if hashlib.sha256(path.read_bytes()).hexdigest() == digest:
                return False
        except OSError:
            pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return True


def stage(data_dir: Path, encoded: str, apply_md: Path | None = None) -> dict:
    pack = decode_pack(encoded)
    target = data_dir / "migration"
    written = _write_atomic(
        target / "pack.json",
        json.dumps(pack, ensure_ascii=False, indent=1).encode("utf-8"),
    )
    text = DEFAULT_APPLY_MD
    if apply_md is not None and apply_md.exists():
        text = apply_md.read_text(encoding="utf-8")
    _write_atomic(target / "APPLY.md", text.encode("utf-8"))
    return {
        "staged": True,
        "pack_written": written,
        "agents": len(pack.get("agents") or []),
        "sections": len(pack.get("sections") or []),
        "routines": len(pack.get("routines") or []),
        "skills": len(pack.get("skills") or []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage the encrypted migration pack")
    parser.add_argument("stage", nargs="?", default="stage", choices=["stage"])
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--apply-md", type=Path, default=None)
    args = parser.parse_args(argv)

    encoded = os.environ.get("OPENBOT_MIGRATION_PACK", "")
    if not encoded.strip():
        print(json.dumps({"staged": False, "reason": "no_pack"}))
        return 0
    try:
        result = stage(args.data, encoded, args.apply_md)
    except ValueError as exc:
        print(json.dumps({"staged": False, "error": str(exc)}))
        print(f"::warning::migration pack rejected: {exc}")
        return 0
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Encrypted /data state store for OpenBot Cloud Gateway.

Versions encrypted /data archives independently of code on parentless git refs
(state/live, state/bak-1, state/bak-2) and fails closed on tampering or rollback.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
import zipfile

BUNDLE = "openbot-bundle.enc"
META = "openbot-bundle.meta.json"
MARKER = ".openbot-state-generation.json"
REFS = ["refs/heads/state/live", "refs/heads/state/bak-1", "refs/heads/state/bak-2"]
MAX_BYTES = 95 * 1024 * 1024  # Keep strictly under GitHub's 100 MiB blob ceiling
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 120_000
ARTIFACT_RE = re.compile(r"^openbot-recovery-bundle-(\d+)-(\d+)-(\d+)$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")

# Volatile caches/sockets/temp dirs excluded so /data stays lean & portable across runners
SKIP_DIR_NAMES = {
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GrShaderCache",
    "GraphiteDawnCache",
    "ShaderCache",
    "Crashpad",
    "Service Worker",
    "blob_storage",
    "Session Storage",
    "Local Storage",
    "VideoDecodeStats",
    "OptimizationGuidePredictionModels",
    "component_crx_cache",
    "extensions_crx_cache",
    "__pycache__",
    "node_modules",
    ".cache",
    ".npm",
    ".cargo",
    "tmp",
    "logs",
}
SKIP_FILE_NAMES = {
    "SingletonLock",
    "SingletonSocket",
    "SingletonCookie",
    "lockfile",
    ".DS_Store",
}
SKIP_SUFFIXES = (".sock", ".pid", ".lock", ".tmp", ".log", "-wal", "-shm")


def run_cmd(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 180) -> str:
    res = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if res.returncode != 0:
        raise RuntimeError(f"{args[0]} {' '.join(args[1:3])} failed (exit {res.returncode}): {res.stderr.strip()[:400]}")
    return res.stdout


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    merged = {**os.environ, **(env or {}), "GIT_TERMINAL_PROMPT": "0"}
    attempts = 3 if args and args[0] in {"ls-remote", "fetch", "push"} else 1
    for attempt in range(attempts):
        try:
            return run_cmd(["git", *args], cwd=repo, env=merged)
        except (RuntimeError, subprocess.TimeoutExpired):
            if attempt + 1 == attempts:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def validate_meta(meta: dict) -> dict:
    if meta.get("format") != 1 or type(meta.get("state_seq")) is not int or meta["state_seq"] < 1:
        raise ValueError("Invalid state_seq or format")
    for field in ("bundle_sha256", "parent_sha256", "lineage_id"):
        if not isinstance(meta.get(field), str) or not HEX64.fullmatch(meta[field]):
            raise ValueError(f"Invalid hash field: {field}")
    if not re.fullmatch(r"[0-9]+", str(meta.get("source_run_id", ""))):
        raise ValueError("Invalid source_run_id")
    if type(meta.get("source_run_attempt")) is not int or meta["source_run_attempt"] < 1:
        raise ValueError("Invalid source_run_attempt")
    stamp = datetime.fromisoformat(meta["created_at_utc"])
    if stamp.utcoffset() is None:
        raise ValueError("Timestamp missing timezone")
    return meta


def inner_marker(meta: dict) -> dict:
    return {k: v for k, v in meta.items() if k != "bundle_sha256"}


def is_sqlite_file(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size < 16:
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def sqlite_online_backup(source: Path, target: Path, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout

    def progress(_status: int, _remaining: int, _total: int) -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"SQLite backup timeout: {source.name}")

    try:
        uri = source.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as src_conn:
            with closing(sqlite3.connect(str(target), timeout=5.0)) as dst_conn:
                src_conn.backup(dst_conn, pages=256, sleep=0.05, progress=progress)
                check = dst_conn.execute("PRAGMA quick_check").fetchone()[0]
                if check != "ok":
                    raise RuntimeError(f"SQLite quick_check failed for {source.name}: {check}")
        os.chmod(target, 0o600)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def create_data_archive(data_dir: Path, destination: Path) -> dict:
    if not data_dir.is_dir():
        raise RuntimeError(f"Data directory missing: {data_dir}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_count = 0
    sqlite_count = 0
    total_bytes = 0

    with tempfile.TemporaryDirectory(prefix="openbot-snap-") as snap_tmp:
        snap_root = Path(snap_tmp)
        with tarfile.open(destination, "w:gz", compresslevel=6) as tar:
            for current, dirs, files in os.walk(data_dir, followlinks=False):
                cur_path = Path(current)
                rel_dir = cur_path.relative_to(data_dir)
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIR_NAMES)
                for dname in list(dirs):
                    dp = cur_path / dname
                    if dp.is_symlink():
                        dirs.remove(dname)
                        arc = (rel_dir / dname).as_posix() if rel_dir != Path(".") else dname
                        tar.add(dp, arcname=arc, recursive=False)
                        file_count += 1
                for fname in sorted(files):
                    if fname in SKIP_FILE_NAMES or fname.endswith(SKIP_SUFFIXES):
                        continue
                    fp = cur_path / fname
                    arc = (rel_dir / fname).as_posix() if rel_dir != Path(".") else fname
                    if fp.is_symlink():
                        tar.add(fp, arcname=arc, recursive=False)
                        file_count += 1
                        continue
                    if not fp.is_file():
                        continue
                    if is_sqlite_file(fp):
                        staged = snap_root / f"db-{sqlite_count}.sqlite"
                        sqlite_online_backup(fp, staged)
                        tar.add(staged, arcname=arc, recursive=False)
                        total_bytes += staged.stat().st_size
                        sqlite_count += 1
                        file_count += 1
                    else:
                        tar.add(fp, arcname=arc, recursive=False)
                        total_bytes += fp.stat().st_size
                        file_count += 1

    return {
        "files": file_count,
        "sqlite_verified": sqlite_count,
        "uncompressed_bytes": total_bytes,
        "archive_bytes": destination.stat().st_size,
    }


def verify_archive(archive_path: Path, meta: dict) -> None:
    validate_meta(meta)
    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError(f"Archive exceeds max member count ({len(members)})")
        names = [m.name for m in members]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive members")
        expanded = 0
        for member in members:
            expanded += max(member.size, 0)
            if expanded > MAX_UNPACKED_BYTES:
                raise ValueError("Archive expands beyond safety limit")
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError(f"Unsafe archive path: {member.name}")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError(f"Unsupported member type: {member.name}")
            tarfile.data_filter(member, "/openbot-restore-root")
        marker_member = tar.getmember(MARKER)
        with tar.extractfile(marker_member) as fh:
            inner = json.load(fh)
        if inner != inner_marker(meta):
            raise ValueError("Inner generation marker mismatches outer metadata")


def openssl_encrypt(plain: Path, bundle: Path) -> None:
    if not os.environ.get("OPENBOT_BUNDLE_KEY"):
        raise RuntimeError("OPENBOT_BUNDLE_KEY environment variable is required")
    bundle.parent.mkdir(parents=True, exist_ok=True)
    run_cmd(
        [
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-salt",
            "-in", str(plain), "-out", str(bundle),
            "-pass", "env:OPENBOT_BUNDLE_KEY",
        ]
    )
    os.chmod(bundle, 0o600)


def openssl_decrypt(bundle: Path, meta: dict, plain_out: Path) -> None:
    if not os.environ.get("OPENBOT_BUNDLE_KEY"):
        raise RuntimeError("OPENBOT_BUNDLE_KEY environment variable is required")
    validate_meta(meta)
    if bundle.stat().st_size > MAX_BYTES:
        raise ValueError("Encrypted bundle exceeds MAX_BYTES")
    if sha256_file(bundle) != meta["bundle_sha256"]:
        raise ValueError("Encrypted bundle SHA-256 mismatch")
    run_cmd(
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "600000",
            "-in", str(bundle), "-out", str(plain_out),
            "-pass", "env:OPENBOT_BUNDLE_KEY",
        ]
    )
    verify_archive(plain_out, meta)


def list_remote_refs(repo: Path) -> dict[str, str]:
    out = git(repo, "ls-remote", "origin", *REFS)
    found: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1] in REFS:
            found[parts[1]] = parts[0]
    return found


def load_ref_candidate(repo: Path, ref: str, sha: str, dest: Path) -> tuple[Path, dict] | None:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        git(repo, "fetch", "--depth=1", "origin", sha)
        meta_raw = git(repo, "show", f"{sha}:{META}")
        meta = validate_meta(json.loads(meta_raw))
        bundle_path = dest / BUNDLE
        res = subprocess.run(
            ["git", "show", f"{sha}:{BUNDLE}"],
            cwd=str(repo),
            capture_output=True,
            timeout=180,
        )
        if res.returncode != 0:
            return None
        bundle_path.write_bytes(res.stdout)
        return (bundle_path, meta)
    except Exception:
        return None


def fetch_recovery_artifacts(work: Path) -> list[tuple[Path, dict]]:
    repo_slug = os.environ.get("GITHUB_REPOSITORY")
    if not repo_slug or not os.environ.get("GH_TOKEN"):
        return []
    candidates: list[tuple[Path, dict]] = []
    try:
        raw = run_cmd(["gh", "api", f"repos/{repo_slug}/actions/artifacts?per_page=30"])
        data = json.loads(raw)
    except Exception:
        return []
    art_root = work / "artifacts"
    art_root.mkdir(parents=True, exist_ok=True)
    for item in data.get("artifacts", []):
        if item.get("expired"):
            continue
        if not ARTIFACT_RE.match(item.get("name", "")):
            continue
        aid = item["id"]
        zip_path = art_root / f"{aid}.zip"
        out_dir = art_root / str(aid)
        try:
            res = subprocess.run(
                ["gh", "api", f"repos/{repo_slug}/actions/artifacts/{aid}/zip"],
                capture_output=True,
                timeout=180,
            )
            if res.returncode != 0:
                continue
            zip_path.write_bytes(res.stdout)
            out_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path) as zf:
                for member in zf.namelist():
                    if member in {BUNDLE, META}:
                        zf.extract(member, out_dir)
            meta = validate_meta(json.loads((out_dir / META).read_text(encoding="utf-8")))
            bundle = out_dir / BUNDLE
            if bundle.is_file():
                candidates.append((bundle, meta))
        except Exception:
            continue
        finally:
            zip_path.unlink(missing_ok=True)
    return candidates


def publish_refs(repo: Path, bundle: Path, meta: dict, current_refs: dict[str, str]) -> dict[str, str]:
    validate_meta(meta)
    if bundle.stat().st_size > MAX_BYTES:
        raise ValueError(f"Bundle too large ({bundle.stat().st_size} B > {MAX_BYTES} B)")
    if sha256_file(bundle) != meta["bundle_sha256"]:
        raise ValueError("Bundle digest mismatch before publish")

    with tempfile.TemporaryDirectory(prefix="openbot-pub-") as tmp:
        stage = Path(tmp)
        env = {
            **os.environ,
            "GIT_INDEX_FILE": str(stage / "index"),
            "GIT_AUTHOR_NAME": "openbot-cloud-gateway[bot]",
            "GIT_AUTHOR_EMAIL": "openbot-cloud-gateway[bot]@users.noreply.github.com",
            "GIT_COMMITTER_NAME": "openbot-cloud-gateway[bot]",
            "GIT_COMMITTER_EMAIL": "openbot-cloud-gateway[bot]@users.noreply.github.com",
        }
        b_hash = git(repo, "hash-object", "-w", str(bundle), env=env).strip()
        meta_file = stage / META
        atomic_json(meta_file, meta)
        m_hash = git(repo, "hash-object", "-w", str(meta_file), env=env).strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{b_hash},{BUNDLE}", env=env)
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{m_hash},{META}", env=env)
        tree = git(repo, "write-tree", env=env).strip()
        msg = f"state: publish openbot generation {meta['state_seq']}"
        commit = subprocess.run(
            ["git", "commit-tree", tree, "-m", msg],
            cwd=str(repo),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        updates: list[str] = [f"{commit}:{REFS[0]}"]
        new_refs: dict[str, str] = {REFS[0]: commit}
        if REFS[0] in current_refs:
            updates.append(f"{current_refs[REFS[0]]}:{REFS[1]}")
            new_refs[REFS[1]] = current_refs[REFS[0]]
        if REFS[1] in current_refs:
            updates.append(f"{current_refs[REFS[1]]}:{REFS[2]}")
            new_refs[REFS[2]] = current_refs[REFS[1]]

        lease_args = []
        for r in REFS:
            if r in current_refs:
                lease_args.append(f"--force-with-lease={r}:{current_refs[r]}")
        git(repo, "push", "--atomic", *lease_args, "origin", *updates)
        return new_refs


def action_restore(repo: Path, work: Path, data_dir: Path | None, allow_bootstrap: bool, read_only: bool) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    refs = list_remote_refs(repo)
    candidates: list[tuple[Path, dict, bool]] = []

    for idx, ref in enumerate(REFS):
        if ref in refs:
            loaded = load_ref_candidate(repo, ref, refs[ref], work / f"ref-{idx}")
            if loaded:
                candidates.append((loaded[0], loaded[1], idx == 0))

    for bundle, meta in fetch_recovery_artifacts(work):
        candidates.append((bundle, meta, False))

    valid: list[tuple[Path, dict, bool, Path]] = []
    for i, (bundle, meta, is_live) in enumerate(candidates):
        plain = work / f"cand-{i}.tar.gz"
        try:
            openssl_decrypt(bundle, meta, plain)
            valid.append((bundle, meta, is_live, plain))
        except Exception:
            plain.unlink(missing_ok=True)

    if not valid:
        if not allow_bootstrap:
            raise RuntimeError("No valid encrypted OpenBot state found and --allow-bootstrap not set")
        ctx = {
            "bootstrapped": False,
            "base": {
                "state_seq": 0,
                "bundle_sha256": "0" * 64,
                "lineage_id": secrets.token_hex(32),
            },
            "refs": refs,
        }
        atomic_json(work / "context.json", ctx)
        return {"bootstrapped": False, "state_seq": 0, "recovered": False}

    valid.sort(key=lambda item: (item[1]["state_seq"], 1 if item[2] else 0), reverse=True)
    best_bundle, best_meta, was_live, best_plain = valid[0]
    for _, _, _, other_plain in valid[1:]:
        other_plain.unlink(missing_ok=True)

    recovered = not was_live
    if recovered and not read_only:
        refs = publish_refs(repo, best_bundle, best_meta, refs)

    if data_dir is not None:
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(best_plain, "r:gz") as tar:
                tar.extractall(data_dir, filter="data")
        finally:
            best_plain.unlink(missing_ok=True)
    else:
        best_plain.unlink(missing_ok=True)

    ctx = {"bootstrapped": True, "base": best_meta, "refs": refs}
    atomic_json(work / "context.json", ctx)
    return {"bootstrapped": True, "state_seq": best_meta["state_seq"], "recovered": recovered}


def action_seal(work: Path, data_dir: Path) -> dict:
    ctx = json.loads((work / "context.json").read_text(encoding="utf-8"))
    prev = ctx["base"]
    pub_dir = work / "publish"
    pub_dir.mkdir(parents=True, exist_ok=True)

    inner = {
        "format": 1,
        "state_seq": int(prev["state_seq"]) + 1,
        "parent_sha256": prev["bundle_sha256"],
        "lineage_id": prev["lineage_id"],
        "source_run_id": os.environ.get("GITHUB_RUN_ID", "0"),
        "source_run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    atomic_json(data_dir / MARKER, inner)

    plain = pub_dir / "state.tar.gz"
    bundle = pub_dir / BUNDLE
    verify_plain = pub_dir / "verify.tar.gz"
    try:
        proof = create_data_archive(data_dir, plain)
        openssl_encrypt(plain, bundle)
        if bundle.stat().st_size > MAX_BYTES:
            raise RuntimeError(f"Encrypted bundle exceeds limit: {bundle.stat().st_size} B > {MAX_BYTES} B")
        meta = {**inner, "bundle_sha256": sha256_file(bundle)}
        openssl_decrypt(bundle, meta, verify_plain)
        atomic_json(pub_dir / META, meta)
        atomic_json(work / "snapshot-proof.json", proof)
    finally:
        plain.unlink(missing_ok=True)
        verify_plain.unlink(missing_ok=True)

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"state_seq={meta['state_seq']}\n")
    return {"sealed_state_seq": meta["state_seq"], "encrypted_bytes": bundle.stat().st_size, **proof}


def action_publish(repo: Path, work: Path) -> dict:
    ctx = json.loads((work / "context.json").read_text(encoding="utf-8"))
    pub_dir = work / "publish"
    meta = validate_meta(json.loads((pub_dir / META).read_text(encoding="utf-8")))
    if meta["state_seq"] != int(ctx["base"]["state_seq"]) + 1:
        raise ValueError("Published generation does not advance restored state_seq by 1")
    if meta["parent_sha256"] != ctx["base"]["bundle_sha256"]:
        raise ValueError("Published generation parent_sha256 mismatch")
    publish_refs(repo, pub_dir / BUNDLE, meta, ctx["refs"])
    return {"published_state_seq": meta["state_seq"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["restore", "seal", "publish"])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--data", type=Path)
    parser.add_argument("--allow-bootstrap", action="store_true")
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()

    if args.action == "restore":
        res = action_restore(args.repo, args.work, args.data, args.allow_bootstrap, args.read_only)
    elif args.action == "seal":
        if not args.data:
            raise SystemExit("--data is required for seal")
        res = action_seal(args.work, args.data)
    else:
        res = action_publish(args.repo, args.work)
    print(json.dumps(res))


if __name__ == "__main__":
    main()

"""Supervise the official OpenBot Docker container on a bounded GitHub Actions cycle."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

CONTAINER = "openbot"
STOP_REQUESTED = False


def handle_signal(_signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def run(args: list[str], *, stdin_text: str | None = None, timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def ensure_userns_allowed() -> list[str]:
    """Ubuntu 24.04 AppArmor may restrict unprivileged userns needed by Electron sandbox."""
    extra_opts: list[str] = []
    sysctl_path = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl_path.exists():
        try:
            if sysctl_path.read_text(encoding="utf-8").strip() == "1":
                extra_opts.extend(["--security-opt", "apparmor=unconfined"])
        except OSError:
            pass
    return extra_opts


def seed_workspace(data_dir: Path, seed_dir: Path) -> None:
    """Copy non-sensitive agent instructions/blueprint into /data/seed-migration once."""
    if not seed_dir.is_dir():
        return
    target = data_dir / "seed-migration"
    if target.exists():
        return
    shutil.copytree(seed_dir, target)


def container_running() -> bool:
    res = run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], timeout=15)
    return res.returncode == 0 and res.stdout.strip() == "true"


def probe_openbot_status() -> tuple[bool, str]:
    if not container_running():
        return False, "container_not_running"
    res = run(["docker", "exec", CONTAINER, "openbot", "status"], timeout=20)
    if res.returncode != 0:
        return False, f"status_exit_{res.returncode}"
    # Redact any accidental email/token lines; keep only safe status keywords
    lines = [
        ln.strip()
        for ln in res.stdout.splitlines()
        if any(k in ln.lower() for k in ("version", "server", "state", "memory", "turns", "status", "online", "connected", "signed"))
    ]
    return True, " | ".join(lines[:4]) if lines else "ok"


def stop_container() -> None:
    if container_running():
        run(["docker", "stop", "--time", "60", CONTAINER], timeout=90)
    run(["docker", "rm", "-f", CONTAINER], timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--seccomp", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--seed", type=Path, default=None)
    parser.add_argument("--server-name", default="OpenBot Cloud")
    parser.add_argument("--max-runtime", type=int, default=17400)
    parser.add_argument("--probe-interval", type=int, default=60)
    parser.add_argument("--bootstrap-only", action="store_true")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    args.data.mkdir(parents=True, exist_ok=True)
    os.chmod(args.data, 0o700)
    if args.seed:
        seed_workspace(args.data, args.seed)

    # Remove stale container if present
    run(["docker", "rm", "-f", CONTAINER], timeout=30)

    cmd = [
        "docker", "run", "-d",
        "--name", CONTAINER,
        "--security-opt", f"seccomp={args.seccomp.resolve()}",
        "--security-opt", "no-new-privileges:true",
        *ensure_userns_allowed(),
        "--shm-size", "1g",
        "--stop-timeout", "60",
        "-e", "TZ=Asia/Jakarta",
        "-v", f"{args.data.resolve()}:/data",
        args.image,
    ]
    start_res = run(cmd, timeout=120)
    if start_res.returncode != 0:
        print(json.dumps({"event": "start_failed", "code": start_res.returncode, "err": start_res.stderr.strip()[:400]}), file=sys.stderr)
        return 1

    try:
        # Wait up to 90s for OpenBot runtime to become responsive to `openbot status`
        ready = False
        last_summary = ""
        for _ in range(30):
            if STOP_REQUESTED:
                break
            ok, summary = probe_openbot_status()
            last_summary = summary
            if ok:
                ready = True
                break
            time.sleep(3)

        if not ready:
            logs = run(["docker", "logs", "--tail", "40", CONTAINER], timeout=15)
            print(json.dumps({"event": "startup_unhealthy", "summary": last_summary, "tail_lines": len(logs.stdout.splitlines())}), file=sys.stderr)
            return 1

        print(json.dumps({"event": "container_ready", "summary": last_summary}), flush=True)

        # One-time claim sign-in if OPENBOT_CLAIM_ONCE is provided and not yet signed in
        claim = os.environ.get("OPENBOT_CLAIM_ONCE", "").strip()
        if claim:
            claim_res = run(
                ["docker", "exec", "-i", CONTAINER, "openbot", "login", "--claim", "--name", args.server_name],
                stdin_text=claim + "\n",
                timeout=120,
            )
            connected = "connected to your account" in (claim_res.stdout + claim_res.stderr).lower()
            already = "already" in (claim_res.stdout + claim_res.stderr).lower()
            print(json.dumps({"event": "claim_attempt", "exit_code": claim_res.returncode, "connected": connected, "already_signed_in": already}), flush=True)
            if claim_res.returncode != 0 and not already:
                return 1
            time.sleep(5)
            ok, summary = probe_openbot_status()
            print(json.dumps({"event": "post_claim_status", "ok": ok, "summary": summary}), flush=True)

        if args.bootstrap_only:
            print(json.dumps({"event": "bootstrap_only_complete"}), flush=True)
            return 0

        # Supervision loop
        started = time.monotonic()
        consecutive_failures = 0
        while not STOP_REQUESTED:
            elapsed = time.monotonic() - started
            if elapsed >= args.max_runtime:
                print(json.dumps({"event": "cycle_complete", "elapsed_s": int(elapsed)}), flush=True)
                break
            sleep_for = min(args.probe_interval, max(1, int(args.max_runtime - elapsed)))
            for _ in range(sleep_for):
                if STOP_REQUESTED:
                    break
                time.sleep(1)
            if STOP_REQUESTED:
                break
            ok, summary = probe_openbot_status()
            if ok:
                consecutive_failures = 0
                print(json.dumps({"event": "probe_ok", "elapsed_s": int(time.monotonic() - started), "summary": summary}), flush=True)
            else:
                consecutive_failures += 1
                print(json.dumps({"event": "probe_fail", "count": consecutive_failures, "summary": summary}), file=sys.stderr, flush=True)
                if consecutive_failures >= 5:
                    return 1
        return 0
    finally:
        print(json.dumps({"event": "graceful_stop_start"}), flush=True)
        stop_container()
        print(json.dumps({"event": "graceful_stop_done"}), flush=True)


if __name__ == "__main__":
    sys.exit(main())

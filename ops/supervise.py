"""Supervise the official OpenBot Docker container on a bounded GitHub Actions cycle."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

CONTAINER = "openbot"
STOP_REQUESTED = False
SENSITIVE_LOG_RE = re.compile(r"(token|claim|secret|password|authorization|cookie)", re.IGNORECASE)


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


def collect_host_security() -> dict[str, object]:
    info: dict[str, object] = {}
    sysctl_path = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl_path.exists():
        try:
            info["apparmor_restrict_unprivileged_userns"] = sysctl_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            info["apparmor_restrict_unprivileged_userns_err"] = str(exc)[:100]
    res = run(["docker", "info", "--format", "{{.SecurityOptions}}"], timeout=15)
    if res.returncode == 0:
        info["docker_security_options"] = sanitize_log_lines(res.stdout, 5)
    return info


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


def write_gh_output(key: str, value: str) -> None:
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


def sanitize_log_lines(text: str, limit: int = 20) -> list[str]:
    safe: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "@" in line or SENSITIVE_LOG_RE.search(line):
            continue
        safe.append(line[:200])
    return safe[-limit:]


def chown_tree(path: Path, owner: str) -> None:
    if not hasattr(os, "getuid"):
        return
    cmd = ["chown", "-Rh", owner, str(path)]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n", *cmd]
    res = run(cmd, timeout=60)
    if res.returncode != 0:
        err = " | ".join(sanitize_log_lines(res.stderr + "\n" + res.stdout, 5))
        raise RuntimeError(f"chown {owner} failed (exit {res.returncode}): {err}")


def probe_openbot_status() -> tuple[bool, str]:
    if not container_running():
        return False, "container_not_running"
    res = run(["docker", "exec", CONTAINER, "openbot", "status"], timeout=20)
    if res.returncode != 0:
        return False, f"status_exit_{res.returncode}"
    if "account: loading" in res.stdout.lower():
        return False, "account_loading"
    # Redact any accidental email/token lines; keep only safe status keywords
    lines: list[str] = []
    for raw in res.stdout.splitlines():
        ln = raw.strip()
        low = ln.lower()
        if not ln or "@" in ln or SENSITIVE_LOG_RE.search(ln):
            continue
        if low.startswith("account:") and "signed out" not in low:
            continue
        if any(k in low for k in ("openbot ", "version", "server:", "account: signed out", "memory:", "turns", "online", "connected")):
            lines.append(ln[:200])
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
    parser.add_argument("--smoke-test", action="store_true")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    args.data.mkdir(parents=True, exist_ok=True)
    os.chmod(args.data, 0o700)
    if args.seed:
        seed_workspace(args.data, args.seed)

    need_chown = hasattr(os, "getuid") and os.getuid() != 1000
    if need_chown:
        try:
            chown_tree(args.data, "1000:1000")
        except Exception as exc:
            print(json.dumps({"event": "chown_failed", "phase": "pre_start", "err": str(exc)[:300]}), file=sys.stderr, flush=True)
            return 1

    # Remove stale container if present
    run(["docker", "rm", "-f", CONTAINER], timeout=30)

    cmd = [
        "docker", "run", "-d",
        "--name", CONTAINER,
        "--security-opt", f"seccomp={args.seccomp.resolve()}",
        "--security-opt", "no-new-privileges:true",
        "--shm-size", "1g",
        "--stop-timeout", "60",
        "-e", "TZ=Asia/Jakarta",
        "-v", f"{args.data.resolve()}:/data",
        args.image,
    ]
    seal_ok = False
    try:
        start_res = run(cmd, timeout=120)
        if start_res.returncode != 0:
            print(json.dumps({"event": "start_failed", "code": start_res.returncode, "err": start_res.stderr.strip()[:400]}), file=sys.stderr, flush=True)
            return 1

        # Wait up to 120s for OpenBot runtime to become responsive to `openbot status`
        ready = False
        last_summary = ""
        for _ in range(40):
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
            tail = sanitize_log_lines(logs.stdout + "\n" + logs.stderr, 20)
            print(json.dumps({"event": "startup_unhealthy", "summary": last_summary, "tail": tail, "host_sec": collect_host_security()}), file=sys.stderr, flush=True)
            return 1

        print(json.dumps({"event": "container_ready", "summary": last_summary}), flush=True)

        if args.smoke_test:
            print(json.dumps({"event": "smoke_test_ok", "summary": last_summary}), flush=True)
            return 0

        # One-time claim sign-in if OPENBOT_CLAIM_ONCE is provided and not yet signed in
        claim = os.environ.get("OPENBOT_CLAIM_ONCE", "").strip()
        if claim:
            claim_res = run(
                ["docker", "exec", "-i", CONTAINER, "openbot", "login", "--claim", "--name", args.server_name],
                stdin_text=claim + "\n",
                timeout=180,
            )
            online = bool(re.search(r"^Server:.*\(online\)", claim_res.stdout, re.IGNORECASE | re.MULTILINE))
            already = (
                claim_res.returncode == 0
                and "publishing the server" not in claim_res.stdout.lower()
                and bool(re.search(r"^OpenBot\s+", claim_res.stdout, re.MULTILINE))
            )
            payload: dict[str, object] = {
                "event": "claim_attempt",
                "exit_code": claim_res.returncode,
                "online": online,
                "already_signed_in": already,
            }
            if claim_res.returncode != 0:
                payload["err_tail"] = sanitize_log_lines(claim_res.stderr, 8)
            print(json.dumps(payload), flush=True)
            if claim_res.returncode != 0:
                return 1
            time.sleep(5)
            ok, summary = probe_openbot_status()
            print(json.dumps({"event": "post_claim_status", "ok": ok, "summary": summary}), flush=True)
            if not ok or "online" not in summary.lower():
                print(json.dumps({"event": "post_claim_not_online", "summary": summary}), file=sys.stderr, flush=True)
                return 1
            seal_ok = True
        elif args.bootstrap_only:
            if "online" not in last_summary.lower():
                print(json.dumps({"event": "bootstrap_not_online", "summary": last_summary}), file=sys.stderr, flush=True)
                return 1
            seal_ok = True
        else:
            seal_ok = True

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
        if need_chown:
            chown_tree(args.data, f"{os.getuid()}:{os.getgid()}")
        if seal_ok:
            write_gh_output("seal_ok", "true")
        print(json.dumps({"event": "graceful_stop_done"}), flush=True)


if __name__ == "__main__":
    sys.exit(main())

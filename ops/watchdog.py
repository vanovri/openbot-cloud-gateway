"""Watchdog: ensure one OpenBot 24x7 Cloud Gateway workflow cycle stays active."""
from __future__ import annotations

import json
import os
import subprocess

ACTIVE_STATUSES = {"queued", "in_progress", "waiting", "pending", "requested"}


def state_bootstrapped(repo: str) -> bool:
    res = subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/heads/state/live"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return res.returncode == 0


def ensure_running(repo: str, workflow: str = "openbot.yml") -> dict:
    if not state_bootstrapped(repo):
        return {"action": "waiting_for_initial_bootstrap"}
    res = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/workflows/{workflow}/runs?per_page=30"],
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
    )
    runs = json.loads(res.stdout).get("workflow_runs", [])
    active = [r for r in runs if r.get("status") in ACTIVE_STATUSES and r.get("head_branch") == "main"]
    if active:
        return {"action": "already_active", "run_ids": [r["id"] for r in active]}
    subprocess.run(
        ["gh", "workflow", "run", workflow, "--repo", repo, "--ref", "main"],
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
    )
    return {"action": "dispatched"}


if __name__ == "__main__":
    print(json.dumps(ensure_running(os.environ["GITHUB_REPOSITORY"])))

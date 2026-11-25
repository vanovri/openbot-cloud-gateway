# OpenBot Cloud Gateway

Runs the official OpenBot self-hosted Docker server (`ghcr.io/nightly-labs/openbot:0.78.0`) on GitHub Actions in bounded 4h50m (`17,400s`) cycles with encrypted `/data` state persistence and 5-minute watchdog recovery — following the exact persistence & supervision architecture of `hermes-cloud-gateway`.

## Architecture
- **Runtime**: `ghcr.io/nightly-labs/openbot:0.78.0` with pinned `docker/seccomp.json`, `--security-opt no-new-privileges:true`, `--shm-size 1g`, `--stop-timeout 60`, `TZ=Asia/Jakarta`, and `-v "$RUNNER_TEMP/openbot-data:/data"`.
- **Encrypted state (`ops/state_store.py`)**:
  - Gracefully stops OpenBot (`docker stop --time 60`) before snapshotting `/data` via SQLite online backup + `PRAGMA quick_check` while excluding volatile browser caches.
  - Encrypts `/data` with AES-256-CBC + PBKDF2 (`600,000` iterations) using repository secret `OPENBOT_BUNDLE_KEY`.
  - Publishes parentless commits atomically to `refs/heads/state/live` while rotating `refs/heads/state/bak-1` and `refs/heads/state/bak-2`, backed by a temporary 5-day encrypted recovery artifact.
- **Supervision & Watchdog (`ops/supervise.py`, `ops/watchdog.py`)**:
  - Actively probes `openbot status` every 60 seconds (5 consecutive failures trigger bounded exit + state seal).
  - `watchdog.yml` checks on `workflow_run` completion and every 5 minutes, dispatching a fresh cycle whenever `state/live` exists and no run is active.
- **Privacy boundary**: Zero plaintext agent prompts, personal data, or client names live in this public repository; all runtime data is stored strictly inside the AES-256 encrypted `/data` state refs.

## Honest Operational Limits
- GitHub Actions schedules can drift or pause; runner handoffs have a ~1–2 minute gap every ~4h50m while `/data` is sealed and the next runner boots.
- Hard runner loss can lose state changes since the previous completed cycle publication.
- Never commit credentials, plaintext `/data`, or `OPENBOT_BUNDLE_KEY`. Keep `OPENBOT_CLAIM_ONCE` strictly ephemeral (delete immediately after initial claim).

## Tests
```bash
python3 -m unittest discover -s tests -v
```

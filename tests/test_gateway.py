"""Unit tests for OpenBot Cloud Gateway state persistence and watchdog."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ops"))
import state_store  # noqa: E402
import supervise  # noqa: E402
import watchdog  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openbot-gw-test-"))
        self.origin = self.tmp / "origin.git"
        self.repo = self.tmp / "repo"
        subprocess.run(["git", "init", "--bare", str(self.origin)], check=True, capture_output=True)
        subprocess.run(["git", "clone", str(self.origin), str(self.repo)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo, check=True)
        (self.repo / "README.md").write_text("init\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=self.repo, check=True)
        subprocess.run(["git", "push", "origin", "HEAD:refs/heads/main"], cwd=self.repo, check=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_sample_data(self, root: Path, value: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "config.json").write_text(json.dumps({"server": value}), encoding="utf-8")
        (root / "Cache").mkdir(exist_ok=True)
        (root / "Cache" / "junk.bin").write_bytes(b"x" * 1024)
        (root / "SingletonLock").write_text("lock", encoding="utf-8")
        db_path = root / "state.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
        conn.execute("INSERT OR REPLACE INTO kv VALUES ('v', ?)", (value,))
        conn.commit()
        conn.close()

    @unittest.skipUnless(HAS_OPENSSL, "openssl CLI required")
    def test_bootstrap_seal_publish_restore_and_backup_rotation(self) -> None:
        env = {
            "OPENBOT_BUNDLE_KEY": "test-passphrase-256bit-verification-key",
            "GITHUB_RUN_ID": "1001",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            # 1. Bootstrap restore on empty remote
            w1 = self.tmp / "work1"
            d1 = self.tmp / "data1"
            r1 = state_store.action_restore(self.repo, w1, d1, allow_bootstrap=True, read_only=False)
            self.assertEqual(r1, {"bootstrapped": False, "state_seq": 0, "recovered": False})

            # 2. Populate /data with SQLite + volatile caches -> seal + publish gen 1
            self._make_sample_data(d1, "gen-1")
            s1 = state_store.action_seal(w1, d1)
            self.assertEqual(s1["sealed_state_seq"], 1)
            self.assertEqual(s1["sqlite_verified"], 1)
            p1 = state_store.action_publish(self.repo, w1)
            self.assertEqual(p1["published_state_seq"], 1)

            # 3. Restore into fresh dir and verify caches excluded + SQLite intact
            w2 = self.tmp / "work2"
            d2 = self.tmp / "data2"
            r2 = state_store.action_restore(self.repo, w2, d2, allow_bootstrap=False, read_only=False)
            self.assertEqual(r2, {"bootstrapped": True, "state_seq": 1, "recovered": False})
            self.assertFalse((d2 / "Cache").exists())
            self.assertFalse((d2 / "SingletonLock").exists())
            conn = sqlite3.connect(str(d2 / "state.db"))
            self.assertEqual(conn.execute("SELECT v FROM kv WHERE k='v'").fetchone()[0], "gen-1")
            conn.close()

            # 4. Advance to gen 2 & gen 3 and verify bak-1 / bak-2 rotation
            self._make_sample_data(d2, "gen-2")
            state_store.action_seal(w2, d2)
            state_store.action_publish(self.repo, w2)

            w3 = self.tmp / "work3"
            d3 = self.tmp / "data3"
            r3 = state_store.action_restore(self.repo, w3, d3, allow_bootstrap=False, read_only=False)
            self.assertEqual(r3["state_seq"], 2)
            self._make_sample_data(d3, "gen-3")
            state_store.action_seal(w3, d3)
            state_store.action_publish(self.repo, w3)

            refs = state_store.list_remote_refs(self.repo)
            self.assertEqual(set(refs.keys()), set(state_store.REFS))
            self.assertEqual(len(set(refs.values())), 3)

    @unittest.skipUnless(HAS_OPENSSL, "openssl CLI required")
    def test_tampered_bundle_fails_closed(self) -> None:
        env = {
            "OPENBOT_BUNDLE_KEY": "test-passphrase-256bit-verification-key",
            "GITHUB_RUN_ID": "2001",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            w = self.tmp / "wt"
            d = self.tmp / "dt"
            state_store.action_restore(self.repo, w, d, allow_bootstrap=True, read_only=False)
            self._make_sample_data(d, "secret-data")
            state_store.action_seal(w, d)
            pub = w / "publish"
            meta = json.loads((pub / state_store.META).read_text(encoding="utf-8"))
            bundle = pub / state_store.BUNDLE
            raw = bytearray(bundle.read_bytes())
            raw[-1] ^= 0xFF
            bundle.write_bytes(bytes(raw))
            with self.assertRaises(ValueError):
                state_store.openssl_decrypt(bundle, meta, self.tmp / "out.tar.gz")


class WatchdogTests(unittest.TestCase):
    def test_watchdog_waits_before_bootstrap(self) -> None:
        with mock.patch.object(watchdog, "state_bootstrapped", return_value=False):
            self.assertEqual(watchdog.ensure_running("vanovri/openbot-cloud-gateway"), {"action": "waiting_for_initial_bootstrap"})

    def test_watchdog_skips_when_active(self) -> None:
        fake = mock.Mock(returncode=0, stdout=json.dumps({"workflow_runs": [{"id": 99, "status": "in_progress", "head_branch": "main"}]}))
        with mock.patch.object(watchdog, "state_bootstrapped", return_value=True), mock.patch("subprocess.run", return_value=fake):
            res = watchdog.ensure_running("vanovri/openbot-cloud-gateway")
            self.assertEqual(res, {"action": "already_active", "run_ids": [99]})

    def test_watchdog_dispatches_when_idle(self) -> None:
        list_res = mock.Mock(returncode=0, stdout=json.dumps({"workflow_runs": [{"id": 98, "status": "completed", "head_branch": "main"}]}))
        disp_res = mock.Mock(returncode=0, stdout="")
        with mock.patch.object(watchdog, "state_bootstrapped", return_value=True), mock.patch("subprocess.run", side_effect=[list_res, disp_res]) as mrun:
            res = watchdog.ensure_running("vanovri/openbot-cloud-gateway")
            self.assertEqual(res, {"action": "dispatched"})
            self.assertEqual(mrun.call_count, 2)


class SuperviseTests(unittest.TestCase):
    def test_sanitize_log_lines_redacts_secrets_and_emails(self) -> None:
        raw = "\n".join([
            "   ",
            "User 1000 cannot write to /data",
            "Account: user@example.com",
            "Authorization: Bearer abc",
            "OPENBOT_CLAIM=xyz",
            "token leaked",
            "password file missing",
            "The virtual display :0 did not start.",
        ])
        self.assertEqual(
            supervise.sanitize_log_lines(raw, limit=10),
            [
                "User 1000 cannot write to /data",
                "The virtual display :0 did not start.",
            ],
        )

    def test_probe_openbot_status_redacts_email_keeps_safe_lines(self) -> None:
        sample = "\n".join([
            "OpenBot 0.78.0",
            "Account: myserver@example.com",
            "Server: OpenBot Cloud (online)",
            "Memory: 3100 MiB free of 7800 MiB (ok)",
            "Turns at the same time: at most 8",
        ])
        fake_exec = mock.Mock(returncode=0, stdout=sample, stderr="")
        with mock.patch.object(supervise, "container_running", return_value=True), mock.patch.object(supervise, "run", return_value=fake_exec):
            ok, summary = supervise.probe_openbot_status()
        self.assertTrue(ok)
        self.assertNotIn("@", summary)
        self.assertIn("Server: OpenBot Cloud (online)", summary)
        self.assertIn("Memory: 3100 MiB free of 7800 MiB (ok)", summary)


if __name__ == "__main__":
    unittest.main()

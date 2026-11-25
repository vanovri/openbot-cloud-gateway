"""Unit tests for the migration pack staging step."""
from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ops"))
import stage_migration  # noqa: E402


def encode(pack: dict) -> str:
    return base64.b64encode(gzip.compress(json.dumps(pack).encode("utf-8"), 9, mtime=0)).decode("ascii")


class StageMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openbot-mig-test-"))
        self.data = self.tmp / "data"

    def test_stage_writes_pack_and_apply(self) -> None:
        pack = {"agents": [{"name": "A"}], "sections": [{"name": "S"}], "routines": []}
        result = stage_migration.stage(self.data, encode(pack))
        self.assertTrue(result["staged"])
        self.assertTrue(result["pack_written"])
        stored = json.loads((self.data / "migration" / "pack.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["agents"][0]["name"], "A")
        self.assertTrue((self.data / "migration" / "APPLY.md").exists())

    def test_stage_is_idempotent(self) -> None:
        pack = {"agents": [], "sections": [], "routines": []}
        stage_migration.stage(self.data, encode(pack))
        again = stage_migration.stage(self.data, encode(pack))
        self.assertFalse(again["pack_written"])

    def test_rejects_broken_pack(self) -> None:
        with self.assertRaises(ValueError):
            stage_migration.decode_pack("not-base64!!")
        with self.assertRaises(ValueError):
            stage_migration.decode_pack(base64.b64encode(b"plain").decode())
        with self.assertRaises(ValueError):
            stage_migration.decode_pack(encode({"agents": []}))

    def test_missing_secret_is_a_noop(self) -> None:
        self.assertEqual(stage_migration.main(["stage", "--data", str(self.data)]), 0)
        self.assertFalse((self.data / "migration").exists())


if __name__ == "__main__":
    unittest.main()

import concurrent.futures
import datetime
import json
from pathlib import Path
import tempfile
import unittest

import test_v6only as base

obs = base.v6.OBSERVABILITY


class ObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "logs"
        self.records = obs.Records(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_credentials_redacted_and_permissions_private(self):
        self.records.append("audit", "fixture", "成功", details={"Authorization": "Bearer fixture-secret", "url": "https://user:pass@example.com/key", "nested": {"api_key": "sk-fixture"}})
        content = next(self.root.glob("*.jsonl")).read_text()
        for secret in ["fixture-secret", "user:pass", "sk-fixture"]:
            self.assertNotIn(secret, content)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(next(self.root.glob("*.jsonl")).stat().st_mode & 0o777, 0o600)

    def test_concurrent_audits_keep_complete_json_records(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda number: self.records.append("audit", str(number), "成功"), range(60)))
        self.assertEqual(len(self.records.read(limit=100)), 60)

    def test_retention_and_capacity_do_not_delete_foreign_files(self):
        self.records.append("health", "probe", "成功")
        old = self.root / "audit-20000101.jsonl"
        old.write_text("old")
        foreign = self.root / "user-notes.txt"
        foreign.write_text("用户数据")
        self.records.prune()
        self.assertFalse(old.exists())
        self.assertEqual(foreign.read_text(), "用户数据")
        self.records.limit = 2048
        for _ in range(12):
            self.records.append("audit", "fixture", "成功", details={"text": "x" * 1000})
        self.assertLessEqual(sum(path.stat().st_size for path in self.root.glob("*.jsonl")), 2048)
        self.assertTrue(self.records.read())

    def test_corrupt_log_record_does_not_hide_other_records(self):
        self.records.append("audit", "fixture", "成功")
        with next(self.root.glob("*.jsonl")).open("a") as stream:
            stream.write('{"broken":true}\nnot-json\n')
        self.assertEqual(len(self.records.read()), 1)

import datetime
import os
from pathlib import Path
import tempfile
import unittest

import test_v6only as base

tx = base.v6.TRANSACTIONS


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.journal = tx.Journal(self.root, self.root / "var/lib/v6only/transactions")

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self):
        target = self.root / "etc/v6only/config.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("original")
        target.chmod(0o640)
        data = self.journal.create("apply", [{"path": "/etc/v6only/config.json", "content": "new"},
                                             {"path": "/etc/v6only/other", "content": "other"}], {}, {})
        return target, data

    def test_no_mutation_until_rollback_armed(self):
        target, data = self.prepare()
        with self.assertRaises(tx.TransactionError):
            self.journal.apply_files(data)
        self.assertEqual(target.read_text(), "original")

    def test_crash_after_partial_write_restores_from_journal(self):
        target, data = self.prepare()
        self.journal.save(data, "rollback_armed")
        def crash(index):
            raise OSError("模拟进程崩溃")
        with self.assertRaises(OSError):
            self.journal.apply_files(data, fault=crash)
        persisted = self.journal.load(data["id"])
        self.journal.restore_files(persisted)
        self.assertEqual(target.read_text(), "original")
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.root / "etc/v6only/other").exists())

    def test_external_changes_are_not_overwritten(self):
        target, data = self.prepare()
        self.journal.save(data, "rollback_armed")
        self.journal.apply_files(data)
        target.write_text("用户后续修改")
        with self.assertRaises(tx.TransactionError) as error:
            self.journal.restore_files(data)
        self.assertEqual(error.exception.code, 5)
        self.assertEqual(target.read_text(), "用户后续修改")
        self.assertEqual((self.root / "etc/v6only/other").read_text(), "other")

    def test_corrupt_backup_stops_before_restore(self):
        target, data = self.prepare()
        self.journal.save(data, "rollback_armed")
        self.journal.apply_files(data)
        (self.journal.directory / data["id"] / "before-0").write_text("损坏")
        with self.assertRaises(tx.TransactionError):
            self.journal.restore_files(data)
        self.assertEqual(target.read_text(), "new")

    def test_expired_or_unapplied_transaction_cannot_confirm(self):
        target, data = self.prepare()
        with self.assertRaises(tx.TransactionError):
            self.journal.confirmable(data)
        self.journal.save(data, "rollback_armed")
        self.journal.apply_files(data)
        self.journal.save(data, "awaiting_confirm")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        with self.assertRaises(tx.TransactionError):
            self.journal.confirmable(data, future)

    def test_rejects_foreign_paths_symlinks_and_hardlinks(self):
        for path in ["/etc/resolv.conf", "/etc/v6only/../ssh/sshd_config", "/root/net-snapshots/old"]:
            with self.assertRaises(tx.TransactionError):
                self.journal.target(path)
        (self.root / "etc").mkdir()
        (self.root / "etc/v6only").symlink_to(self.root / "outside")
        with self.assertRaises(tx.TransactionError):
            self.journal.inspect("/etc/v6only/config")

    def test_external_extended_metadata_is_not_silently_lost(self):
        target, data = self.prepare()
        os.setxattr(target, "user.v6only-fixture", b"keep")
        self.journal.save(data, "rollback_armed")
        with self.assertRaises(tx.TransactionError):
            self.journal.apply_files(data)
        self.assertEqual(os.getxattr(target, "user.v6only-fixture"), b"keep")
        self.assertEqual(target.read_text(), "original")


if __name__ == "__main__":
    unittest.main()

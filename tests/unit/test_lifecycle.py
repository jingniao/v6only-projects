import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_v6only as base

v6 = base.v6


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.host = v6.HOST.SandboxHost(self.root)
        self.manager = v6.RUNTIME.Manager(self.host, v6.TRANSACTIONS, v6.HOST, v6.OBSERVABILITY,
                                          {"singbox": v6.SINGBOX, "dnsmasq": v6.DNSMASQ})
        self.policy = v6.HOST.policy_defaults()
        self.policy.update(include_uids=[1000], dns_upstream="192.0.2.53", health_domains=["api.openai.com"])
        self.entry = self.root / "dist-v6only"
        self.entry.write_bytes(b"#!/usr/bin/env bash\n# V6ONLY_PY_SIMULATION\n")

    def tearDown(self):
        self.temporary.cleanup()

    def install(self, confirm=True):
        result = self.manager.execute("install", ["*.openai.com"], policy=self.policy, entry=self.entry, broad=True)
        if confirm:
            self.manager.confirm(result["transaction"])
        return result

    def test_install_requires_confirmation_and_is_idempotent(self):
        result = self.install(False)
        self.assertEqual(result["mode"], "simulation")
        self.assertEqual(self.manager.read()["active_transaction"], result["transaction"])
        self.assertIn(result["transaction"], self.host.timers)
        self.assertTrue(self.manager.status()["effective_enabled"])
        self.assertEqual(json.loads((self.manager.directory / "state.json").read_text())["domains"], ["*.openai.com"])
        self.manager.confirm(result["transaction"])
        self.assertTrue(self.manager.read()["installed"])
        self.assertNotIn(result["transaction"], self.host.timers)
        repeated = self.manager.execute("install", [], policy=self.policy, broad=True)
        self.assertFalse(repeated["changed"])

    def test_owned_entry_is_updated_from_a_new_verified_artifact(self):
        self.install()
        updated = b"#!/usr/bin/env bash\n# V6ONLY_PY_SIMULATION_UPDATED\n"
        self.entry.write_bytes(updated)
        state = self.manager.read()
        self.manager.bootstrap(self.entry, state, refresh=True)
        self.assertEqual((self.root / "usr/local/sbin/v6only").read_bytes(), updated)

    def test_wrong_confirmation_never_cancels_other_timer(self):
        result = self.install(False)
        self.host.timers["other"] = "其他项目定时器"
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.confirm("a" * 32)
        self.assertIn(result["transaction"], self.host.timers)
        self.assertIn("other", self.host.timers)

    def test_timer_restores_after_process_restart(self):
        result = self.install(False)
        restarted = v6.RUNTIME.Manager(self.host, v6.TRANSACTIONS, v6.HOST, v6.OBSERVABILITY,
                                        {"singbox": v6.SINGBOX, "dnsmasq": v6.DNSMASQ})
        restarted.recover(result["transaction"], automatic=True)
        self.assertFalse(restarted.read()["installed"])
        self.assertFalse(self.host.running)
        self.assertFalse(self.host.tables)
        self.assertFalse(restarted.recover(result["transaction"], automatic=True)["changed"])

    def test_arm_failure_never_applies_files_or_network(self):
        self.host.fail = "arm"
        with self.assertRaises(v6.HOST.HostError):
            self.install()
        self.assertFalse((self.root / "etc/v6only/singbox.json").exists())
        self.assertFalse(self.host.tables)

    def test_health_failure_restores_previous_backend(self):
        self.install()
        old = (self.root / "etc/v6only/singbox.json").read_bytes()
        self.host.fail = "health_once"
        with self.assertRaises(v6.RUNTIME.RuntimeError) as error:
            self.manager.execute("apply", ["claude.ai"], broad=True)
        self.assertEqual(error.exception.code, 4)
        self.assertEqual((self.root / "etc/v6only/singbox.json").read_bytes(), old)
        self.assertTrue(self.manager.read()["enabled"])
        self.assertEqual(self.manager.read()["domains"], ["*.openai.com"])

    def test_backend_switch_failure_recovers_singbox(self):
        self.install()
        self.host.fail = "start_once"
        with self.assertRaises(v6.HOST.HostError):
            self.manager.execute("backend", [], backend="dnsmasq", downgrade=True)
        self.assertEqual(self.manager.read()["backend"], "singbox")
        self.assertIn("v6only-singbox.service", self.host.running)
        self.assertFalse((self.root / "etc/v6only/dns-front.conf").exists())

    def test_restore_failure_keeps_snapshots_and_timer(self):
        result = self.install()
        self.host.fail = "start"
        with self.assertRaises(v6.RUNTIME.RuntimeError) as error:
            self.manager.execute("reinstall", [], broad=True)
        self.assertEqual(error.exception.code, 5)
        active = self.manager.read()["active_transaction"]
        self.assertTrue(active)
        self.assertTrue((self.manager.journal.directory / active / "journal.json").exists())
        self.assertIn(active, self.host.timers)

    def test_conflict_stops_rollback_without_overwriting(self):
        result = self.install()
        path = self.root / "etc/v6only/singbox.json"
        path.write_text("用户改动")
        with self.assertRaises(v6.RUNTIME.RuntimeError) as error:
            self.manager.recover(result["transaction"])
        self.assertEqual(error.exception.code, 5)
        self.assertEqual(path.read_text(), "用户改动")

    def test_disable_enable_uninstall_purge_keep_logs(self):
        self.install()
        disabled = self.manager.execute("disable", [])
        self.manager.confirm(disabled["transaction"])
        self.assertFalse(self.manager.read()["enabled"])
        self.assertFalse(self.host.tables)
        self.assertFalse(self.host.running)
        enabled = self.manager.execute("enable", [], broad=True)
        self.manager.confirm(enabled["transaction"])
        removed = self.manager.execute("uninstall", [])
        self.manager.confirm(removed["transaction"])
        self.assertFalse(self.manager.read()["installed"])
        self.assertTrue((self.root / "usr/local/sbin/v6only").exists())
        result = self.manager.purge(confirmed=True, keep_logs=True)
        self.assertTrue(result["kept_logs"])
        self.assertTrue((self.root / "var/log/v6only").exists())
        self.assertFalse(self.manager.directory.exists())

    def test_downgrade_and_broad_block_require_explicit_choice(self):
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.execute("install", [], policy=self.policy, entry=self.entry)
        self.install()
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.execute("backend", [], backend="dnsmasq")

    def test_committed_timer_is_harmless_after_commit_replay(self):
        result = self.install()
        replay = self.manager.recover(result["transaction"], automatic=True)
        self.assertEqual(replay["status"], "committed")
        self.assertTrue(self.manager.read()["installed"])

    def test_purge_requires_verified_uninstall(self):
        self.install()
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.purge(True)

    def test_purge_refuses_unknown_files(self):
        self.install()
        removed = self.manager.execute("uninstall", [])
        self.manager.confirm(removed["transaction"])
        unknown = self.root / "opt/v6only/user-notes.txt"
        unknown.write_text("用户文件")
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.purge(True)
        self.assertEqual(unknown.read_text(), "用户文件")
        self.assertTrue(self.manager.path.exists())

    def test_upgrade_failure_restores_binary_and_management_entry(self):
        self.install()
        original_binary = (self.root / "opt/v6only/bin/sing-box").read_bytes()
        original_entry = (self.root / "usr/local/sbin/v6only").read_bytes()
        new_binary = self.root / "new-backend"
        new_binary.write_bytes(b"SIMULATED-NEW-BINARY")
        new_entry = self.root / "new-entry"
        new_entry.write_bytes(b"#!/usr/bin/env bash\n# V6ONLY_PY_NEW\n")
        self.host.fail = "health_once"
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.execute("update", [], binary=new_binary, entry=new_entry, broad=True)
        self.assertEqual((self.root / "opt/v6only/bin/sing-box").read_bytes(), original_binary)
        self.assertEqual((self.root / "usr/local/sbin/v6only").read_bytes(), original_entry)

    def test_uninstall_verifies_network_before_removing_component_files(self):
        self.install()
        def inspect_removal(index):
            self.assertFalse(self.host.running)
            self.assertFalse(self.host.tables)
        removed = self.manager.execute("uninstall", [], fault=inspect_removal)
        self.manager.confirm(removed["transaction"])

    def test_kept_logs_can_be_purged_later_and_entry_removal_is_explicit(self):
        self.install()
        removed = self.manager.execute("uninstall", [])
        self.manager.confirm(removed["transaction"])
        self.manager.purge(True, keep_logs=True)
        self.assertTrue((self.root / "var/log/v6only/retained-resources.json").exists())
        self.manager.purge(True, remove_entry=True)
        self.assertFalse((self.root / "var/log/v6only").exists())
        self.assertFalse((self.root / "usr/local/sbin/v6only").exists())

    def test_independent_recovery_uses_saved_ssh_peer_without_environment(self):
        host = v6.HOST.Host()
        before = {"ssh_peer": "198.51.100.7", "ssh_route": {"dev": "eth0", "gateway": "192.0.2.1", "prefsrc": "old", "table": "main"}}
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(host, "route", return_value={"dev": "eth0", "gateway": "192.0.2.1", "prefsrc": "new", "table": "main"}) as route:
            result = host.health({"enabled": False, "services": []}, before)
        self.assertTrue(result["ok"])
        route.assert_called_once_with("198.51.100.7")

    def test_leftover_rollback_timer_blocks_purge(self):
        installed = self.install()
        removed = self.manager.execute("uninstall", [])
        self.manager.confirm(removed["transaction"])
        timer = self.root / "etc/systemd/system" / ("v6only-rollback-" + installed["transaction"] + ".timer")
        timer.write_text("用户修改的任务")
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.purge(True)
        self.assertTrue(timer.exists())
        self.assertTrue(self.manager.path.exists())


if __name__ == "__main__":
    unittest.main()

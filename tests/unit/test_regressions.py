"""B1/B3 回归测试：后端重启不再误判冲突；restore_failed 可恢复。"""
import tempfile
import unittest
from pathlib import Path

import test_v6only as base

v6 = base.v6


class KernelOwnershipTests(unittest.TestCase):
    """B1：sing-box auto_route 规则/路由不得被误判为外部修改。"""

    def setUp(self):
        self.host = v6.HOST.Host()
        self.policy = v6.HOST.policy_defaults()
        self.policy.update(include_uids=[1500], route_table=47620, rule_priority=12000)
        # 快照只含 install_uid_rules 安装的规则（后端重启前采集）
        self.snapshot = {
            "rules": [
                {"family": "-4", "rule": {"priority": 12000, "table": "main", "src": "all", "uid_start": 1500, "uid_end": 1500}},
                {"family": "-4", "rule": {"priority": 12001, "table": "47620", "src": "all", "uid_start": 1500, "uid_end": 1500}},
            ],
            "routes": [], "addresses": [],
        }

    def _with_live(self, live):
        self.host.kernel_snapshot = lambda policy: live
        return self.host.kernel_conflicts(self.policy, self.snapshot)

    def test_backend_restart_rules_are_not_conflicts(self):
        live = {
            "rules": self.snapshot["rules"] + [
                {"family": "-4", "rule": {"priority": 12016, "table": "47620", "src": "all"}},
                {"family": "-6", "rule": {"priority": 12016, "table": "47620", "src": "all"}},
            ],
            "routes": [{"family": "-6", "route": {"dst": "::/0", "dev": "v6only0"}}],
            "addresses": [{"family": "inet6", "local": "fdfe:dcba:9876::1", "prefixlen": 126, "scope": "global"}],
        }
        self.assertFalse(self._with_live(live))

    def test_tun_address_only_is_not_conflict(self):
        live = {"rules": list(self.snapshot["rules"]), "routes": [],
                "addresses": [{"family": "inet", "local": "172.31.255.1", "prefixlen": 30, "scope": "global"}]}
        self.assertFalse(self._with_live(live))

    def test_unrelated_rule_still_reports_conflict(self):
        live = {"rules": self.snapshot["rules"] + [{"family": "-4", "rule": {"priority": 500, "table": "main", "src": "all"}}],
                "routes": [], "addresses": []}
        self.assertTrue(self._with_live(live))

    def test_uid_rule_for_other_uid_in_range_is_conflict(self):
        # 同一优先级区间但 UID 不在接管清单：必须仍判为冲突
        live = {"rules": self.snapshot["rules"] + [{"family": "-4", "rule": {"priority": 12050, "table": "main", "src": "all", "uid_start": 4242, "uid_end": 4242}}],
                "routes": [], "addresses": []}
        self.assertTrue(self._with_live(live))

    def test_none_snapshot_is_never_a_conflict(self):
        self.assertFalse(self.host.kernel_conflicts(self.policy, None))


class RecoverFromRestoreFailedTests(unittest.TestCase):
    """B3：restore_failed 状态必须可被 recover() 处理，不再永久卡死。"""

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

    def _install(self):
        result = self.manager.execute("install", ["*.openai.com"], backend="singbox",
                                      policy=self.policy, entry=self.entry, broad=True)
        return result["transaction"]

    def test_restore_failed_then_recover_succeeds(self):
        active = self._install()
        # 注入：恢复阶段健康检查失败 -> restore_failed
        self.host.fail = "health"
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.recover(active)
        self.assertEqual(self.manager.journal.load(active)["status"], "restore_failed")
        # 修复后：允许从 restore_failed 恢复，不再永久卡死
        self.host.fail = None
        outcome = self.manager.recover(active)
        self.assertEqual(outcome["status"], "restored")
        self.assertIsNone(self.manager.read()["active_transaction"])
        self.assertEqual(self.manager.journal.load(active)["status"], "restored")

    def test_check_returns_readonly_diagnostics_when_restore_failed(self):
        active = self._install()
        self.host.fail = "health"
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.recover(active)
        report = self.manager.check()
        self.assertTrue(report["restore_failed"])
        self.assertIn("kernel_live", report)

class InterruptedTransactionTests(unittest.TestCase):
    """B7：被中断且未确认的事务必须可只读诊断、可恢复，不再永久卡死。"""

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

    def _install(self):
        result = self.manager.execute("install", ["*.openai.com"], backend="singbox",
                                      policy=self.policy, entry=self.entry, broad=True)
        return result["transaction"]

    def test_check_reports_interrupted_transaction_instead_of_deadlock(self):
        active = self._install()
        # 模拟进程在 arm() 之后、确认之前被中断
        self.manager.journal.save(self.manager.journal.load(active), "rollback_armed")
        report = self.manager.check()
        self.assertFalse(report["ok"])
        self.assertTrue(report["diagnostic"])
        self.assertEqual(report["transaction_status"], "rollback_armed")
        self.assertIn("kernel_live", report)

    def test_status_gives_guidance_for_interrupted_transaction(self):
        active = self._install()
        self.manager.journal.save(self.manager.journal.load(active), "prepared")
        result = self.manager.status()
        self.assertEqual(result["transaction_status"], "prepared")
        self.assertIn("中断", result["说明"])

    def test_interrupted_transaction_can_be_rolled_back(self):
        active = self._install()
        self.manager.journal.save(self.manager.journal.load(active), "prepared")
        outcome = self.manager.recover(active)
        self.assertEqual(outcome["status"], "restored")
        self.assertIsNone(self.manager.read()["active_transaction"])
        self.assertEqual(self.manager.journal.load(active)["status"], "restored")


class SnapshotSettleTests(unittest.TestCase):
    """B2：auto_route 落地前的缺项快照不得永久阻塞清理；采集前必须等窗口稳定。"""

    def setUp(self):
        self.host = v6.HOST.Host()
        self.policy = v6.HOST.policy_defaults()
        self.policy.update(include_uids=[1500], route_table=47620, rule_priority=12000)
        self.issued = []
        self.host.command = self._command

    def _command(self, *args, **kwargs):
        self.issued.append(args[0] if args else [])
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    @staticmethod
    def _uid_rule():
        return {"family": "-4", "rule": {"priority": 12016, "table": "47620", "src": "all"}}

    @staticmethod
    def _late_route():
        return {"family": "-6", "route": {"dst": "::/0", "dev": "v6only0"}}

    def test_cleanup_accepts_late_project_owned_routes(self):
        """快照缺项（auto_route 尚未落地）时，项目自身的路由仍可被清理，不再 exit 5。"""
        reads = [
            {"rules": [self._uid_rule()], "routes": [self._late_route()], "addresses": []},
            {"rules": [], "routes": [], "addresses": []},
        ]
        self.host.kernel_snapshot = lambda policy: reads.pop(0) if reads else {"rules": [], "routes": [], "addresses": []}
        self.host.cleanup_kernel(self.policy, {"rules": [], "routes": [], "addresses": []})
        self.assertTrue(any("route" in args for args in self.issued))

    def test_cleanup_still_refuses_foreign_resources(self):
        """真正的用户改动（非项目优先级区间、非项目表）仍必须拒绝清理。"""
        foreign = {"family": "-4", "rule": {"priority": 30000, "table": "main", "src": "all"}}
        self.host.kernel_snapshot = lambda policy: {"rules": [foreign], "routes": [], "addresses": []}
        with self.assertRaises(v6.HOST.HostError):
            self.host.cleanup_kernel(self.policy, {"rules": [], "routes": [], "addresses": []})

    def test_wait_settled_waits_for_late_auto_route(self):
        """窗口在后端启动后才补齐时必须等它稳定，否则采集到缺项快照。"""
        empty = {"rules": [self._uid_rule()], "routes": [], "addresses": []}
        full = {"rules": [self._uid_rule()], "routes": [self._late_route()], "addresses": []}
        reads = [empty, empty, empty, full, full, full, full, full]
        self.host.kernel_snapshot = lambda policy: reads.pop(0) if reads else full
        self.assertTrue(self.host.wait_settled(self.policy, quiet=0.2, limit=5.0, interval=0.05))
        self.assertEqual(self.host.kernel_snapshot(self.policy), full)

    def test_wait_settled_gives_up_on_unstable_window(self):
        counter = {"n": 0}

        def changing(policy):
            counter["n"] += 1
            rule = {"family": "-4", "rule": {"priority": 12016 + counter["n"], "table": "47620", "src": "all"}}
            return {"rules": [rule], "routes": [], "addresses": []}

        self.host.kernel_snapshot = changing
        self.assertFalse(self.host.wait_settled(self.policy, quiet=0.2, limit=0.5, interval=0.05))

"""BUG-15-01 回归测试：回滚恢复路径必须在内核窗口稳定后再采集 kernel_snapshot。

实机对照（第 15 轮）：超时自动回滚后 runtime.json.kernel_snapshot = rules 3 / routes 0 / addresses 2，
而同一时刻实机为 rules 29 / routes 33 / addresses 2。缺项快照未记录 auto_route 生成的
goto / nop / iif lo / dport 53 等规则，这些规则不落在 UID 归属优先级区间，
于是被 kernel_conflicts 判为「外部资源」，导致后续 check / apply 一律 exit 5 死锁。
"""
import tempfile
import unittest
from pathlib import Path

import test_v6only as base

v6 = base.v6


class RestoreSnapshotSettleTests(unittest.TestCase):
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
        # auto_route 落地后才会出现的规则：优先级在项目 UID 区间之外，故一旦不在快照内即被判定为外部资源。
        self.auto_route_rule = {"family": "-4", "rule": {"priority": 12016, "table": "main", "src": "all"}}
        self.full = {"rules": [self.auto_route_rule], "routes": [], "addresses": []}
        self.short = {"rules": [], "routes": [], "addresses": []}
        # settled 表示「内核窗口是否已自行补齐」：真实内核不管有没有人等，稍后都会补齐。
        self.settled = True
        self.order = []
        self.host.kernel_snapshot = self._snapshot
        self.host.wait_ready = self._ready
        self.host.wait_settled = self._settle

    def tearDown(self):
        self.temporary.cleanup()

    def _snapshot(self, policy):
        self.order.append("kernel_snapshot")
        source = self.full if self.settled else self.short
        return {key: list(source[key]) for key in ("rules", "routes", "addresses")}

    def _ready(self, state, deadline):
        self.order.append("wait_ready")

    def _settle(self, policy, deadline=None, **kwargs):
        self.order.append("wait_settled")
        self.settled = True
        return True

    def _rollback_second_transaction(self):
        """安装并确认后，再 apply 一个变更并回滚它，使恢复目标为「已启用」状态。"""
        install = self.manager.execute("install", ["*.openai.com"], policy=self.policy, entry=self.entry, broad=True)
        self.manager.confirm(install["transaction"])
        second = self.manager.execute("apply", ["*.openai.com", "claude.ai"], broad=True)["transaction"]
        self.settled = False  # 回滚时内核窗口刚开始重新落地
        self.order.clear()
        self.assertEqual(self.manager.recover(second)["status"], "restored")
        return second

    def test_rollback_waits_for_settle_before_snapshot(self):
        """wait_ready 之后必须先 wait_settled，再采集并写回 kernel_snapshot。"""
        self._rollback_second_transaction()
        self.assertIn("wait_settled", self.order)
        self.assertLess(self.order.index("wait_ready"), self.order.index("wait_settled"))
        self.assertIn("kernel_snapshot", self.order[self.order.index("wait_settled") + 1:])
        self.assertEqual(self.manager.read()["kernel_snapshot"], self.full)

    def test_check_is_ok_after_rollback(self):
        """回滚后窗口补齐，check 必须通过，不得因残缺快照报「归属资源发生外部变化」并 exit 5。"""
        self._rollback_second_transaction()
        self.settled = True  # 内核窗口随后自行补齐；此时实机资源已完整
        report = self.manager.check()
        self.assertTrue(report["ok"])
        self.assertIsNone(self.manager.read()["active_transaction"])

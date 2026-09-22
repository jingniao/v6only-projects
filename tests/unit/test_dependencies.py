from pathlib import Path
import subprocess
import tempfile
import unittest

import test_v6only as base

v6 = base.v6


class PackageHost(v6.HOST.SandboxHost):
    def __init__(self, root):
        super().__init__(root)
        self.packages = {}
        self.fail_install = False

    def command(self, args, input=None, check=True, timeout=30):
        if args[0] == "dpkg-query":
            package = args[-1]
            return subprocess.CompletedProcess(args, 0 if package in self.packages else 1, self.packages.get(package, ""), "")
        if args[0] == "env":
            policy = self.root / "usr/sbin/policy-rc.d"
            if "exit 101" not in policy.read_text():
                raise AssertionError("安装时没有禁止自启")
            if self.fail_install:
                raise v6.HOST.HostError("模拟 APT 失败", 4)
            for package in args[args.index("install") + 1:]:
                self.packages[package] = "installed 1.0-test"
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("测试中出现未允许的外部命令")


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.host = PackageHost(self.root)
        self.manager = v6.RUNTIME.Manager(self.host, v6.TRANSACTIONS, v6.HOST, v6.OBSERVABILITY, {})
        self.policy = self.root / "usr/sbin/policy-rc.d"
        self.policy.parent.mkdir(parents=True)
        self.policy.write_text("#!/bin/sh\n# 用户原有策略\nexit 0\n")
        self.policy.chmod(0o751)
        self.before = self.policy.read_bytes()

    def tearDown(self):
        self.temp.cleanup()

    def test_installer_restores_original_policy_and_tracks_packages(self):
        result = self.manager.install_dependencies(["nftables"], v6.RUNTIME.initial_state())
        self.assertEqual(self.policy.read_bytes(), self.before)
        self.assertEqual(self.policy.stat().st_mode & 0o777, 0o751)
        self.assertEqual(result["dependency_records"][0]["before"]["nftables"], "未安装")
        self.assertIn("installed", result["dependency_records"][0]["after"]["nftables"])
        self.assertFalse(self.host.timers)

    def test_apt_failure_still_restores_autostart_policy(self):
        self.host.fail_install = True
        with self.assertRaises(v6.HOST.HostError):
            self.manager.install_dependencies(["nftables"], v6.RUNTIME.initial_state())
        self.assertEqual(self.policy.read_bytes(), self.before)
        self.assertIsNone(self.manager.read()["dependency_pending"])

    def test_unlisted_packages_are_rejected_before_changes(self):
        with self.assertRaises(v6.RUNTIME.RuntimeError):
            self.manager.install_dependencies(["unrelated-package"], v6.RUNTIME.initial_state())
        self.assertEqual(self.policy.read_bytes(), self.before)
        self.assertFalse(self.manager.path.exists())

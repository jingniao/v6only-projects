import json
import resource
import subprocess
import unittest

import test_v6only as base


class PreviewTests(unittest.TestCase):
    setUp = base.CLITests.setUp
    tearDown = base.CLITests.tearDown
    cli = base.CLITests.cli
    snapshot = base.CLITests.snapshot

    def test_install_preview_contains_concrete_network_config_without_writes(self):
        before = self.snapshot()
        result = self.cli("install", "--policy", str(base.ROOT / "examples/policy.json.example"), "--dry-run")
        plan = json.loads(result.stdout)
        self.assertEqual(plan["candidate"]["inbounds"][-1]["type"], "tun")
        self.assertEqual(plan["candidate"]["inbounds"][-1]["dns_mode"], "disabled")
        self.assertIn("dnat ip to 127.0.0.1", plan["nft_candidate"])
        self.assertFalse(plan["writes"])
        self.assertEqual(self.snapshot(), before)

    def test_dnsmasq_candidate_roundtrip_and_dry_validation(self):
        self.cli("add", "openai.com", "*.claude.ai")
        result = self.cli("config", "render", "--backend", "dnsmasq", "--dns-server", "192.0.2.53")
        candidate = json.loads(result.stdout)
        self.assertEqual(candidate["backend"], "dnsmasq")
        target = self.root / "candidate.json"
        target.write_text(result.stdout)
        before = self.snapshot()
        self.cli("config", "validate", str(target), "--binary", "/not-installed", "--dry-run")
        self.assertEqual(self.snapshot(), before)

    def test_purge_preview_respects_keep_logs_and_entry_choice(self):
        result = json.loads(self.cli("purge", "--keep-logs", "--remove-entry", "--dry-run").stdout)
        self.assertIn("保留所有项目日志", result["steps"])
        self.assertIn("删除未被改动的管理入口", result["steps"])

    def test_dry_run_works_when_regular_file_writes_are_forbidden(self):
        def no_file_writes():
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        result = subprocess.run(["bash", str(base.ENTRY), "apply", "--dry-run"], env=self.env,
                                capture_output=True, text=True, timeout=15, preexec_fn=no_file_writes)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("规则", json.loads(result.stdout))
        self.assertFalse(self.state.exists())

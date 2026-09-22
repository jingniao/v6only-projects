"""使用已验证缓存中的官方二进制进行配置构造校验；不启动后端。"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("v6only", ROOT / "src/lib/v6only.py")
v6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v6)
BINARY = ROOT / ".cache/sing-box-1.14.1/sing-box"


class OfficialStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise RuntimeError("缺少官方校验器；先显式运行 tools/fetch_singbox.py。")
        verified = json.loads((BINARY.parent / "verified.json").read_text())
        lock = json.loads((ROOT / "tools/singbox-release.json").read_text())
        if verified["archive_sha256"] != lock["archive_sha256"] or hashlib.sha256(BINARY.read_bytes()).hexdigest() != verified["binary_sha256"]:
            raise RuntimeError("缓存的官方校验器摘要发生变化，拒绝执行。")

    def test_pinned_version(self):
        self.assertEqual(v6.SINGBOX.probe(BINARY)["version"], "1.14.1")

    def test_valid_rule_variants(self):
        for domains in [[], ["openai.com"], ["*.openai.com"], ["*.openai.com", "openai.com"],
                        ["*.xn--bcher-kva.de", "xn--bcher-kva.de"]]:
            with self.subTest(domains=domains):
                candidate = v6.SINGBOX.render(domains, 0, "192.0.2.53")
                result = v6.SINGBOX.validate(candidate, BINARY, v6.normalize)
                self.assertTrue(result["syntax_checked"])
                self.assertFalse(result["runtime_verified"])

    def test_example_candidate(self):
        candidate = json.loads((ROOT / "templates/singbox-candidate.example.json").read_text())
        self.assertTrue(v6.SINGBOX.validate(candidate, BINARY, v6.normalize)["syntax_checked"])

    def test_ipv6_dns_upstream(self):
        candidate = v6.SINGBOX.render(["*.openai.com"], 0, "2001:db8::53")
        self.assertTrue(v6.SINGBOX.validate(candidate, BINARY, v6.normalize)["syntax_checked"])

    def test_runtime_tun_config_is_constructible_without_starting_it(self):
        policy = v6.HOST.policy_defaults()
        policy.update(include_uids=[1000], dns_upstream="192.0.2.53", health_domains=["api.openai.com"])
        result = v6.SINGBOX.validate_runtime(["*.openai.com", "openai.com"], policy, BINARY)
        self.assertTrue(result["syntax_checked"])
        self.assertFalse(result["runtime_verified"])

    def test_official_checker_rejects_invalid_outbound(self):
        config = v6.SINGBOX.render([], 0, "192.0.2.53")["config"]
        config["outbounds"][0]["type"] = "v6only-invalid-fixture"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(config))
            result = subprocess.run([str(BINARY), "check", "-c", str(path)], cwd=directory,
                                    capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v6only-invalid-fixture", result.stdout + result.stderr)

    def test_distribution_validates_real_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", str(ROOT / "dist/v6only"), "config", "validate",
                                     str(ROOT / "templates/singbox-candidate.example.json"), "--binary", str(BINARY)],
                                    env=dict(os.environ, V6ONLY_STATE_DIR=str(Path(directory) / "absent")),
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["syntax_checked"])
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()

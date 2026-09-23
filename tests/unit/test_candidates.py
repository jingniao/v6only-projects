"""候选配置的策略边界、调用约束与失败保护。"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest import mock

import test_v6only as base

ROOT, v6 = base.ROOT, base.v6

backend = v6.SINGBOX


class CandidateTests(unittest.TestCase):
    def candidate(self):
        return backend.render(["*.openai.com", "api.anthropic.com"], 2, "192.0.2.53")

    def test_only_subdomains_match_generated_regex(self):
        matcher = backend.domain_matcher(["*.openai.com"])
        expression = matcher["domain_regex"][0]
        for host in ["api.openai.com", "a.b.openai.com", "API.OpenAI.COM", "api.openai.com."]:
            self.assertIsNotNone(re.search(expression, host), host)
        for host in ["openai.com", "abcopenai.com", "openai.com.evil.example", "-x.openai.com", "a..openai.com"]:
            self.assertIsNone(re.search(expression, host), host)

    def test_ipv4_guard_is_domain_scoped_and_precedes_strict_route(self):
        rules = self.candidate()["config"]["route"]["rules"]
        self.assertEqual(rules[1]["type"], "logical")
        self.assertEqual(rules[1]["mode"], "and")
        self.assertEqual(rules[1]["action"], "reject")
        self.assertEqual(rules[1]["rules"][0], backend.domain_matcher(["*.openai.com", "api.anthropic.com"]))
        self.assertIn("0.0.0.0/0", rules[1]["rules"][1]["ip_cidr"])
        self.assertEqual(rules[2]["strategy"], "ipv6_only")
        self.assertEqual(rules[3], rules[1])
        self.assertEqual(rules[4]["outbound"], "strict-ipv6")

    def test_empty_list_never_emits_catch_all_strict_rule(self):
        config = backend.render([], 0, "2001:db8::53")["config"]
        self.assertEqual(config["route"]["rules"], [{"action": "sniff"},
                         {"action": "resolve", "server": "upstream", "strategy": "prefer_ipv6"}])

    def test_invalid_dns_endpoints_rejected(self):
        for address in ["dns.example.com", "https://dns.example.com/dns-query", "1.1.1.1:53",
                        "fe80::1%eth0", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "::ffff:192.0.2.53"]:
            with self.subTest(address=address), self.assertRaises(backend.BackendFailure):
                backend.render([], 0, address)

    def test_runtime_doh_requires_pinned_bootstrap(self):
        server = backend.runtime_dns_server("https://dns.google/dns-query?bootstrap=2001:4860:4860::8844")
        self.assertEqual(server["type"], "https")
        self.assertEqual(server["server"], "2001:4860:4860::8844")
        self.assertEqual(server["tls"]["server_name"], "dns.google")
        for value in ["https://dns.google/dns-query", "http://dns.google/dns-query?bootstrap=1.1.1.1",
                      "https://dns.google/other?bootstrap=1.1.1.1", "https://dns.google/dns-query?bootstrap=fe80::1",
                      "https://dns.google/dns-query?bootstrap=1.1.1.1&x=1"]:
            with self.subTest(value=value), self.assertRaises(backend.BackendFailure):
                backend.runtime_dns_server(value)

    def test_runtime_config_accepts_strict_doh_policy(self):
        policy = v6.HOST.policy_defaults()
        policy.update(include_uids=[1000], health_domains=["google.com"],
                      dns_upstream="https://dns.google/dns-query?bootstrap=2001:4860:4860::8844")
        self.assertEqual(v6.HOST.validate_policy(policy)["dns_upstream"], policy["dns_upstream"])
        self.assertEqual(backend.runtime_config([], policy)["dns"]["servers"][0]["type"], "https")

    def test_no_runtime_resources_or_legacy_fields(self):
        candidate = self.candidate()
        config = candidate["config"]
        self.assertEqual(config["inbounds"], [])
        self.assertEqual(config["log"], {"disabled": True})
        self.assertFalse(candidate["runtime_verified"])
        payload = backend.canonical(config)
        for unsupported in ["domain_strategy", "auto_route", "auto_redirect", "cache_file", "clash_api", "rule_set", "experimental"]:
            self.assertNotIn('"' + unsupported + '"', payload)

    def test_modified_candidate_rejected_even_with_recomputed_digest(self):
        for change in [lambda c: c["config"].update(inbounds=[{"type": "tun"}]),
                       lambda c: c["config"]["log"].update(output="/tmp/no-write"),
                       lambda c: c.update(runtime_verified=True),
                       lambda c: c.update(backend_version="1.14.2"),
                       lambda c: c.update(source_revision=True),
                       lambda c: c["domains"].append("https://bad.example")]:
            candidate = self.candidate()
            change(candidate)
            candidate["config_sha256"] = hashlib.sha256(backend.canonical(candidate["config"]).encode()).hexdigest()
            with mock.patch.object(backend, "invoke") as invoke, self.assertRaises(backend.BackendFailure):
                backend.validate(candidate, "/does/not/exist", v6.normalize)
            invoke.assert_not_called()

    def test_backend_version_mismatch_rejected(self):
        for version in ["1.14.0", "1.14.1-beta.1", "1.14.1-custom", "1.15.0"]:
            with mock.patch.object(backend, "binary_path", return_value=Path("/trusted/sing-box")), \
                 mock.patch.object(backend, "invoke", return_value=subprocess.CompletedProcess([], 0, "sing-box version " + version + "\n")):
                with self.assertRaises(backend.BackendFailure) as error:
                    backend.probe("/trusted/sing-box")
                self.assertEqual(error.exception.code, 3)

    def test_checker_timeout_is_reported_as_failure(self):
        with mock.patch.object(backend.subprocess, "run", side_effect=subprocess.TimeoutExpired("check", 15)):
            with self.assertRaises(backend.BackendFailure) as error:
                backend.invoke("/trusted/sing-box", ["check"])
        self.assertEqual(error.exception.code, 4)

    def test_checker_failure_cleans_temporary_files(self):
        temporary_paths = []
        def fail_check(binary, args, cwd=None):
            temporary_paths.append(Path(cwd))
            self.assertEqual(args[0], "check")
            self.assertEqual(json.loads(Path(args[2]).read_text()), self.candidate()["config"])
            return subprocess.CompletedProcess([], 1, "测试注入：配置校验失败")
        with mock.patch.object(backend, "probe", return_value={"binary": "/trusted/sing-box"}), \
             mock.patch.object(backend, "invoke", side_effect=fail_check):
            with self.assertRaises(backend.BackendFailure):
                backend.validate(self.candidate(), "/trusted/sing-box", v6.normalize)
        self.assertTrue(temporary_paths)
        self.assertFalse(temporary_paths[0].exists())

    def test_example_matches_current_renderer(self):
        candidate = json.loads((ROOT / "templates/singbox-candidate.example.json").read_text())
        self.assertEqual(backend.verify_candidate(candidate, v6.normalize), candidate)


class CandidateCLITests(unittest.TestCase):
    setUp = base.CLITests.setUp
    tearDown = base.CLITests.tearDown
    cli = base.CLITests.cli
    snapshot = base.CLITests.snapshot

    def test_render_preview_has_no_writes(self):
        before = self.snapshot()
        result = self.cli("config", "render", "--dns-server", "192.0.2.53", "--output", str(self.root / "candidate.json"), "--dry-run")
        candidate = json.loads(result.stdout)
        self.assertEqual(candidate["config"]["inbounds"], [])
        self.assertEqual(self.snapshot(), before)

    def test_candidate_export_does_not_modify_pending_state(self):
        self.cli("add", "*.openai.com")
        before = (self.state / "state.json").read_bytes()
        target = self.root / "candidate.json"
        self.cli("config", "render", "--dns-server", "192.0.2.53", "--output", str(target))
        candidate = json.loads(target.read_text())
        self.assertEqual(candidate["domains"], ["*.openai.com"])
        self.assertEqual(candidate["source_revision"], 1)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.state / "state.json").read_bytes(), before)
        self.cli("config", "render", "--dns-server", "192.0.2.53", "--output", str(target), code=3)

    def test_validate_dry_run_never_executes_binary(self):
        target = self.root / "candidate.json"
        target.write_text(json.dumps(backend.render([], 0, "192.0.2.53")))
        before = self.snapshot()
        self.cli("config", "validate", str(target), "--binary", "/not-installed", "--dry-run")
        self.cli("backend", "probe", "singbox", "--binary", "/not-installed", "--dry-run")
        self.assertEqual(self.snapshot(), before)

    def test_invalid_candidate_and_missing_binary_fail_distinctly(self):
        target = self.root / "candidate.json"
        target.write_text("{}")
        self.cli("config", "validate", str(target), "--binary", "/not-installed", code=4)
        target.write_text(json.dumps(backend.render([], 0, "192.0.2.53")))
        self.cli("config", "validate", str(target), "--binary", "/not-installed", code=3)


if __name__ == "__main__":
    unittest.main()

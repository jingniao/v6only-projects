"""纯本地测试，所有数据位于临时目录，不安装软件或修改网络。"""
import concurrent.futures
import importlib.util
import json
import os
import pty
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("v6only", ROOT / "src/lib/v6only.py")
v6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v6)
ENTRY = Path(os.environ.get("V6ONLY_TEST_ENTRY", str(ROOT / "src/v6only.sh")))


class DomainTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(v6.normalize("*.OpenAI.COM."), "*.openai.com")
        self.assertEqual(v6.normalize("XN--BCHER-KVA.de"), "xn--bcher-kva.de")

    def test_invalid_inputs(self):
        for value in ["https://openai.com", "1.2.3.4", "::1", "*.127.0.0.1", "example.com:443",
                      "example.com/a", "x.*.com", "*openai.com", "-x.com", "x-.com", "x..com",
                      "x.com..", "a" * 64 + ".com", "中文.cn", "xn--a.com", "xn--abc-.com",
                      "x.com\x00", "x.com\t", "a_b.com", "$(touch /tmp/owned).com", "localhost"]:
            with self.subTest(value=value), self.assertRaises(v6.Failure):
                v6.normalize(value)

    def test_length_boundary(self):
        domain = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(domain), 253)
        self.assertEqual(v6.normalize(domain), domain)
        with self.assertRaises(v6.Failure):
            v6.normalize(domain + "b")

    def test_exact_and_wildcard_boundaries(self):
        for host, exact, wildcard in [("openai.com", True, False), ("api.openai.com", False, True),
                                      ("a.b.openai.com", False, True), ("abcopenai.com", False, False),
                                      ("openai.com.evil.example", False, False)]:
            with self.subTest(host=host):
                self.assertEqual(v6.matches("openai.com", host), exact)
                self.assertEqual(v6.matches("*.openai.com", host), wildcard)

    def test_comments_crlf_and_deduplication(self):
        self.assertEqual(v6.parse_domains("# 示例\r\nOpenAI.com.\r\n*.openai.com # 注释\nopenai.com\n"),
                         ["*.openai.com", "openai.com"])
        for value in ["openai.com#bad", "openai.com\vbad.com", "openai.com\x00", "openai.com\rhidden"]:
            with self.assertRaises(v6.Failure):
                v6.parse_domains(value)

    def test_documented_fixture(self):
        self.assertEqual(v6.parse_domains((ROOT / "tests/fixtures/domains-valid.txt").read_text()),
                         ["*.openai.com", "api.anthropic.com", "openai.com", "xn--bcher-kva.de"])


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.live_root = self.root / "live"
        self.live_root.mkdir()
        self.env = dict(os.environ, V6ONLY_STATE_DIR=str(self.state), V6ONLY_ROOT=str(self.live_root),
                        PYTHONDONTWRITEBYTECODE="1")

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, *args, code=0):
        result = subprocess.run(["bash", str(ENTRY), *args], env=self.env, text=True,
                                input="", capture_output=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.stat().st_mode, p.stat().st_mtime_ns,
                p.read_bytes() if p.is_file() else None) for p in self.root.rglob("*")}

    def test_edit_roundtrip_and_history(self):
        self.cli("add", "OpenAI.com.", "*.openai.com")
        self.cli("add", "openai.com")
        self.assertEqual(self.cli("list").stdout.splitlines(), ["*.openai.com", "openai.com"])
        self.cli("remove", "openai.com")
        destination = self.root / "export.txt"
        self.cli("export", str(destination))
        self.assertEqual(destination.read_text(), "*.openai.com\n")
        self.cli("remove", "*.openai.com")
        self.cli("import", str(destination))
        history = [json.loads(x) for x in self.cli("history").stdout.splitlines()]
        self.assertEqual([x["revision"] for x in history], [1, 2, 3, 4])
        self.assertNotIn("added", json.loads(self.cli("logs").stdout.splitlines()[0]))
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state / "state.json").stat().st_mode & 0o777, 0o600)

    def test_dry_runs_never_create_state(self):
        source = self.root / "input.txt"
        source.write_text("openai.com\n")
        before = self.snapshot()
        for args in [("add", "*.openai.com"), ("remove", "openai.com"), ("import", str(source)),
                     ("export", str(self.root / "output.txt")), ("apply",)]:
            self.cli(*args, "--dry-run")
        self.cli("--dry-run", "add", "openai.com")
        self.assertEqual(self.snapshot(), before)

    def test_dry_run_does_not_change_existing_state(self):
        self.cli("add", "openai.com")
        before = self.snapshot()
        self.cli("add", "*.openai.com", "--dry-run")
        self.cli("remove", "openai.com", "--dry-run")
        preview = json.loads(self.cli("apply", "--dry-run").stdout)
        self.assertEqual(preview["规则"][0]["类型"], "精确")
        self.assertEqual(self.snapshot(), before)

    def test_invalid_import_is_atomic(self):
        self.cli("add", "openai.com")
        source = self.root / "input.txt"
        source.write_text("claude.ai\nhttps://bad.example/key-secret\n")
        before = self.snapshot()
        result = self.cli("import", str(source), code=2)
        self.assertNotIn("key-secret", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_utf8_and_control_characters(self):
        source = self.root / "input.txt"
        source.write_bytes(b"\xff\n")
        self.cli("import", str(source), code=2)
        self.assertFalse(self.state.exists())

    def test_export_never_overwrites(self):
        destination = self.root / "user.txt"
        destination.write_text("用户数据")
        self.cli("export", str(destination), code=3)
        self.assertEqual(destination.read_text(), "用户数据")

    def test_concurrent_edits_do_not_lose_updates(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda n: self.cli("add", f"host{n}.example.com"), range(18)))
        self.assertEqual(len(results), 18)
        self.assertEqual(len(self.cli("list").stdout.splitlines()), 18)
        self.assertEqual(len(self.cli("history").stdout.splitlines()), 18)

    def test_corrupt_state_is_preserved(self):
        self.cli("add", "openai.com")
        path = self.state / "state.json"
        for content in ['{"domains":', '{"schema":1,"revision":0,"domains":[],"events":[{}]}']:
            path.write_text(content)
            before = path.read_bytes()
            self.cli("add", "claude.ai", code=4)
            self.assertEqual(path.read_bytes(), before)

    def test_optimized_python_still_rejects_invalid_state(self):
        self.cli("add", "openai.com")
        data = json.loads((self.state / "state.json").read_text())
        data["domains"] = ["https://example.com"]
        (self.state / "state.json").write_text(json.dumps(data))
        self.env["PYTHONOPTIMIZE"] = "1"
        self.cli("check", code=4)

    def test_argument_error_does_not_echo_credentials(self):
        result = self.cli("--token=secret-fixture-only", code=2)
        self.assertNotIn("secret-fixture-only", result.stdout + result.stderr)

    def test_shell_input_is_never_executed(self):
        marker = self.root / "should-not-exist"
        self.cli("add", f"$(touch {marker}).com", code=2)
        self.assertFalse(marker.exists())
        self.assertFalse(self.state.exists())

    def test_interactive_menu_retains_standard_input(self):
        master, slave = pty.openpty()
        process = subprocess.Popen(["bash", str(ENTRY)], stdin=slave, stdout=slave,
                                   stderr=slave, env=self.env)
        os.close(slave)
        try:
            os.write(master, b"2\nOpenAI.COM.\n\n0\n")
            process.wait(timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(self.cli("list").stdout, "openai.com\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_symlink_and_insecure_directory_rejected(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        self.state.symlink_to(actual)
        self.cli("add", "openai.com", code=3)
        self.assertEqual(list(actual.iterdir()), [])
        self.state.unlink()
        self.state.mkdir(mode=0o755)
        self.cli("add", "openai.com", code=3)

    def test_runtime_commands_require_authorization_without_writes(self):
        before = self.snapshot()
        commands = [(x,) for x in sorted(v6.LIFECYCLE | {"confirm", "rollback", "purge"})]
        commands += [("backend", "use", "dnsmasq"), ("apply",)]
        for command in commands:
            result = self.cli(*command, code=3)
            self.assertTrue(result.stderr)
            self.cli(*command, "--dry-run")
        self.cli("test", "api.openai.com", "--dry-run")
        self.assertEqual(self.snapshot(), before)

    def test_read_only_and_noninteractive_commands(self):
        for args in [(), ("help",), ("version",), ("list",), ("status",), ("check",),
                     ("doctor",), ("history",), ("logs",)]:
            self.cli(*args)
        self.assertFalse(self.state.exists())
        self.cli("unknown", code=2)
        self.cli("add", code=2)

    def test_explicit_state_directory(self):
        other = self.root / "other"
        self.cli("--state-dir", str(other), "add", "openai.com")
        self.assertFalse(self.state.exists())
        self.assertEqual(self.cli("list", "--state-dir", str(other)).stdout, "openai.com\n")

    def test_atomic_replace_failure_preserves_original(self):
        self.cli("add", "openai.com")
        path = self.state / "state.json"
        before = path.read_bytes()
        with mock.patch.object(v6.os, "replace", side_effect=OSError("故障注入")):
            with self.assertRaises(OSError):
                v6.atomic_write(path, "invalid", replace=True)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(self.state.glob(".v6only-*")), [])


if __name__ == "__main__":
    unittest.main()

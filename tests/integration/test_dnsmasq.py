"""真实 dnsmasq 回环端口测试；不更改系统解析器或网络规则。"""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dnsmasq_backend", ROOT / "src/backends/dnsmasq.py")
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
BINARY = ROOT / ".cache/dnsmasq-2.91/extracted/usr/sbin/dnsmasq"


def encode_name(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


def question(packet):
    offset = 12
    labels = []
    while packet[offset]:
        count = packet[offset]
        labels.append(packet[offset + 1:offset + count + 1].decode())
        offset += count + 1
    offset += 1
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return ".".join(labels), qtype, offset + 4


def skip_name(packet, offset):
    while packet[offset]:
        if packet[offset] & 0xc0 == 0xc0:
            return offset + 2
        offset += packet[offset] + 1
    return offset + 1


def answer_types(packet):
    offset = skip_name(packet, 12) + 4
    count = struct.unpack("!H", packet[6:8])[0]
    kinds = []
    for _ in range(count):
        offset = skip_name(packet, offset)
        kind, _, _, size = struct.unpack("!HHIH", packet[offset:offset + 10])
        kinds.append(kind)
        offset += 10 + size
    return kinds


class DNSFixture:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            name, kind, end = question(packet)
            records = []
            def add(rrtype, value):
                records.append(b"\xc0\x0c" + struct.pack("!HHIH", rrtype, 1, 30, len(value)) + value)
            if name.startswith("alias."):
                add(5, encode_name("target.fixture.example"))
            if kind == 1:
                add(1, ipaddress.ip_address("192.0.2.10").packed)
            elif kind == 28:
                add(28, ipaddress.ip_address("2001:db8::10").packed)
            elif kind in (64, 65):
                add(kind, struct.pack("!H", 1) + b"\0" + struct.pack("!HH", 4, 4) + ipaddress.ip_address("192.0.2.10").packed)
            response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, len(records), 0, 0) + packet[12:end] + b"".join(records)
            self.socket.sendto(response, peer)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.socket.close()


class DNSMasqIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.exists():
            raise RuntimeError("缺少已验证的 dnsmasq 2.91 本地缓存。")
        import hashlib
        lock = json.loads((ROOT / "tools/dnsmasq-release.json").read_text())
        if hashlib.sha256(BINARY.read_bytes()).hexdigest() != lock["binary_sha256"]:
            raise RuntimeError("dnsmasq 缓存摘要不匹配。")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.upstream = DNSFixture()
        self.processes = []
        # 预先检查三个端口；绑定仅限回环地址。
        for _ in range(100):
            port = random.randint(20000, 50000)
            sockets = []
            try:
                for number in range(port, port + 3):
                    for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                            s = socket.socket(family, kind)
                            sockets.append(s)
                            s.bind((host, number))
                self.port = port
                break
            except OSError:
                pass
            finally:
                for s in sockets:
                    s.close()
        else:
            self.fail("无法找到空闲回环测试端口")

    def tearDown(self):
        for process in self.processes:
            process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        self.upstream.close()
        self.temporary.cleanup()

    def query(self, name, kind=1):
        query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", kind, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(query, ("127.0.0.1", self.port))
            response, _ = client.recvfrom(4096)
            self.assertEqual(response[:2], query[:2])
            self.assertEqual(response[3] & 15, 0)
            return answer_types(response)

    def start(self, domains):
        configs = backend.configs(sorted(domains), "127.0.0.1", self.port)
        for name in ("normal", "filtered", "front"):
            content = configs[name]
            if name != "front":
                content = content.replace("server=127.0.0.1\n", f"server=127.0.0.1#{self.upstream.port}\n")
            path = Path(self.temporary.name) / (name + ".conf")
            path.write_text(content)
            result = subprocess.run([str(BINARY), "--test", "--conf-file=" + str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.processes.append(subprocess.Popen([str(BINARY), "--keep-in-foreground", "--conf-file=" + str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        for _ in range(30):
            for process in self.processes:
                if process.poll() is not None:
                    self.fail(process.communicate()[1].decode())
            try:
                self.query("ready.fixture.example")
                return
            except (TimeoutError, socket.timeout):
                time.sleep(0.03)
        self.fail("DNS 测试实例未就绪")

    def test_exact_only_does_not_include_children(self):
        self.start(["openai.com"])
        self.assertNotIn(1, self.query("openai.com"))
        self.assertIn(1, self.query("api.openai.com"))
        self.assertIn(1, self.query("abcopenai.com"))

    def test_wildcard_excludes_root_and_similar_names(self):
        self.start(["*.openai.com"])
        self.assertIn(1, self.query("openai.com"))
        self.assertNotIn(1, self.query("api.openai.com"))
        self.assertNotIn(1, self.query("a.b.openai.com"))
        self.assertIn(1, self.query("openai.com.evil.example"))
        self.assertIn(1, self.query("abcopenai.com"))

    def test_overlapping_exact_and_wildcards(self):
        self.start(["*.openai.com", "api.openai.com", "claude.ai"])
        self.assertNotIn(1, self.query("x.api.openai.com"))
        self.assertNotIn(1, self.query("claude.ai"))
        self.assertIn(1, self.query("api.claude.ai"))

    def test_cname_aaaa_and_address_hints(self):
        self.start(["*.openai.com", "openai.com"])
        self.assertIn(5, self.query("alias.openai.com"))
        self.assertNotIn(1, self.query("alias.openai.com"))
        self.assertIn(28, self.query("api.openai.com", 28))
        for kind in (64, 65):
            self.assertNotIn(kind, self.query("openai.com", kind))
            self.assertIn(kind, self.query("normal.example", kind))

    def test_filter_failure_has_no_unfiltered_fallback(self):
        self.start(["*.openai.com"])
        self.processes[1].terminate()
        self.processes[1].communicate(timeout=3)
        name = "uncached.openai.com"
        query = struct.pack("!HHHHHH", 77, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(query, ("127.0.0.1", self.port))
            try:
                response, _ = client.recvfrom(4096)
                self.assertNotIn(1, answer_types(response))
                self.assertNotEqual(response[3] & 15, 0)
            except socket.timeout:
                pass
        self.assertIn(1, self.query("normal.example"))


if __name__ == "__main__":
    unittest.main()

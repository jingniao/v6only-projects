"""真实 TUN/FakeIP 测试：所有网卡、规则和后端都位于独立网络命名空间。"""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / ".cache/sing-box-1.14.1/sing-box"
SELF = Path(__file__).resolve()


def guarded_command(args, **kwargs):
    forbidden = int(os.environ["V6ONLY_PARENT_NETNS"])
    if os.stat("/proc/self/ns/net").st_ino == forbidden:
        raise RuntimeError("安全检查失败：测试仍处于宿主机默认网络命名空间")
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10, **kwargs)


def wire_name(value):
    return b"".join(bytes([len(label)]) + label.encode() for label in value.split(".")) + b"\0"


def read_line(process, timeout=10):
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        raise RuntimeError("隔离测试进程响应超时")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("隔离测试进程提前退出")
    return json.loads(line)


def peer():
    # 第二个隔离命名空间充当 DNS 和 IPv4/IPv6 服务端。
    guarded_command(["ip", "link", "set", "lo", "up"])
    print(json.dumps({"pid": os.getpid(), "netns": os.stat('/proc/self/ns/net').st_ino}), flush=True)
    start = json.loads(sys.stdin.readline())
    if start.get("action") != "start":
        return
    guarded_command(["ip", "link", "set", "v6peer", "up"])
    guarded_command(["ip", "addr", "add", "192.0.2.1/24", "dev", "v6peer"])
    guarded_command(["ip", "-6", "addr", "add", "2001:db8::1/64", "dev", "v6peer", "nodad"])
    counts = {"ipv4": 0, "ipv6": 0, "udp6": 0, "tls4": 0, "tls6": 0, "peer_ipv6": None, "peer_ipv4": None}
    stop = threading.Event()
    count_lock = threading.Lock()
    dns_enabled = threading.Event()
    dns_enabled.set()

    def tcp(family, host, label, encrypted=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if encrypted else None
        if context:
            context.load_cert_chain(start["certificate"], start["key"])
        def handle(connection, peer_address):
            with count_lock:
                counts[label] += 1
                if family == socket.AF_INET6:
                    counts["peer_ipv6"] = peer_address[0]
                else:
                    counts["peer_ipv4"] = peer_address[0]
            try:
                if context:
                    connection = context.wrap_socket(connection, server_side=True)
                with connection:
                    connection.settimeout(3)
                    payload = b""
                    while len(payload) < len(b"fixture"):
                        block = connection.recv(len(b"fixture") - len(payload))
                        if not block:
                            return
                        payload += block
                    connection.sendall(label.encode())
            except (OSError, ssl.SSLError):
                connection.close()
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, 8444 if encrypted else 8443))
            listener.listen()
            listener.settimeout(0.1)
            while not stop.is_set():
                try:
                    connection, peer_address = listener.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=handle, args=(connection, peer_address), daemon=True).start()

    def udp6():
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as listener:
            listener.bind(("2001:db8::1", 8443))
            listener.settimeout(0.1)
            while not stop.is_set():
                try:
                    _, address = listener.recvfrom(1024)
                except socket.timeout:
                    continue
                counts["udp6"] += 1
                listener.sendto(b"udp6", address)

    def dns():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("192.0.2.1", 53))
            listener.settimeout(0.1)
            while not stop.is_set():
                try:
                    packet, address = listener.recvfrom(4096)
                except socket.timeout:
                    continue
                offset = 12
                labels = []
                while packet[offset]:
                    size = packet[offset]
                    labels.append(packet[offset + 1:offset + 1 + size].decode())
                    offset += size + 1
                end = offset + 5
                kind = struct.unpack("!H", packet[offset + 1:offset + 3])[0]
                name = ".".join(labels)
                if not dns_enabled.is_set():
                    listener.sendto(packet[:2] + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + packet[12:end], address)
                    continue
                body = b""
                if kind == 1:
                    answer = ipaddress.ip_address("192.0.2.1").packed
                elif kind == 28 and "only-a" not in name and name not in {"matched.test", "exact.test", "child.exact.test"}:
                    answer = ipaddress.ip_address("2001:db8::1").packed
                else:
                    answer = None
                if answer:
                    body = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(answer)) + answer
                response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, int(answer is not None), 0, 0) + packet[12:end] + body
                listener.sendto(response, address)

    threads = [threading.Thread(target=fn, args=args, daemon=True) for fn, args in
               [(tcp, (socket.AF_INET, "192.0.2.1", "ipv4")), (tcp, (socket.AF_INET6, "2001:db8::1", "ipv6")),
                (tcp, (socket.AF_INET6, "2001:db8::1", "tls6", True)), (tcp, (socket.AF_INET, "192.0.2.1", "tls4", True)), (dns, ()), (udp6, ())]]
    for thread in threads:
        thread.start()
    time.sleep(0.1)
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        if line.strip() == "counts":
            print(json.dumps(counts), flush=True)
        if line.strip() in {"dns-off", "dns-on"}:
            dns_enabled.set() if line.strip() == "dns-on" else dns_enabled.clear()
            print(json.dumps({"dns_enabled": dns_enabled.is_set()}), flush=True)
        if line.strip() == "pod-route":
            guarded_command(["ip", "route", "replace", "198.51.100.0/24", "via", "192.0.2.2", "dev", "v6peer"])
            print(json.dumps({"ready": True}), flush=True)
        if line.strip() == "stop":
            break
    stop.set()


CLIENT = r'''
import ipaddress,json,os,socket,ssl,struct,sys
os.setgroups([]);os.setgid(1000);os.setuid(1000)
try:
    if sys.argv[1] in ('dns','dns_tcp'):
        name=sys.argv[2]
        packet=struct.pack('!HHHHHH',123,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
        tcp=sys.argv[1]=='dns_tcp'
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM);s.settimeout(4)
        if tcp:
            s.connect(('127.0.0.53',53));s.sendall(struct.pack('!H',len(packet))+packet)
            size=struct.unpack('!H',s.recv(2))[0];data=b''
            while len(data)<size:data+=s.recv(size-len(data))
        else:
            s.sendto(packet,('127.0.0.53',53));data,_=s.recvfrom(4096)
        print(json.dumps({'ok':True,'address':str(ipaddress.ip_address(data[-4:]))}))
    else:
        address=sys.argv[2];udp=sys.argv[1]=='udp'
        if sys.argv[1]=='tls_libc':address=socket.getaddrinfo(address,8444,socket.AF_INET6,socket.SOCK_STREAM)[0][4][0]
        family=socket.AF_INET6 if ':' in address else socket.AF_INET
        s=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(4)
        s.connect((address,8444 if sys.argv[1] in ('tls','tls_libc') else 8443))
        if sys.argv[1] in ('tls','tls_libc'):
            context=ssl.create_default_context(cadata=sys.argv[3]);s=context.wrap_socket(s,server_hostname='dual.matched.test')
        s.send(b'fixture')
        reply=s.recv(1024).decode()
        print(json.dumps({'ok':bool(reply),'reply':reply}))
except OSError as exc:
    print(json.dumps({'ok':False,'category':type(exc).__name__}))
'''


def container_client():
    guarded_command(["ip", "link", "set", "lo", "up"])
    print(json.dumps({"pid": os.getpid(), "netns": os.stat('/proc/self/ns/net').st_ino}), flush=True)
    if sys.stdin.readline().strip() != "start":
        return
    guarded_command(["ip", "link", "set", "podeth", "up"])
    guarded_command(["ip", "addr", "add", "198.51.100.2/24", "dev", "podeth"])
    guarded_command(["ip", "route", "add", "default", "via", "198.51.100.1"])
    os.setgroups([]);os.setgid(1000);os.setuid(1000)
    with socket.create_connection(("192.0.2.1", 8443), timeout=5) as connection:
        connection.sendall(b"fixture")
        print(json.dumps({"reply": connection.recv(1024).decode()}), flush=True)


class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        guarded_command(["ip", "link", "set", "lo", "up"])
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        certificate, key = cls.directory / "fixture-cert.pem", cls.directory / "fixture-key.pem"
        guarded_command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=dual.matched.test",
                         "-addext", "subjectAltName=DNS:dual.matched.test", "-keyout", str(key), "-out", str(certificate)])
        cls.certificate = certificate.read_text()
        cls.peer = subprocess.Popen(["unshare", "--net", sys.executable, "-B", str(SELF), "--peer"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        peer_info = read_line(cls.peer)
        if peer_info["netns"] == os.stat("/proc/self/ns/net").st_ino:
            raise RuntimeError("服务端未隔离")
        guarded_command(["ip", "link", "add", "v6up", "type", "veth", "peer", "name", "v6peer"])
        guarded_command(["ip", "link", "set", "v6peer", "netns", str(peer_info["pid"])])
        guarded_command(["ip", "link", "set", "v6up", "up"])
        guarded_command(["ip", "addr", "add", "192.0.2.2/24", "dev", "v6up"])
        guarded_command(["ip", "-6", "addr", "add", "2001:db8::2/64", "dev", "v6up", "nodad"])
        guarded_command(["ip", "route", "add", "default", "via", "192.0.2.1"])
        guarded_command(["ip", "-6", "route", "add", "default", "via", "2001:db8::1"])
        cls.peer.stdin.write(json.dumps({"action": "start", "certificate": str(certificate), "key": str(key)}) + "\n");cls.peer.stdin.flush()
        read_line(cls.peer)
        spec = importlib.util.spec_from_file_location("v6only", ROOT / "src/lib/v6only.py")
        cls.app = importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.app)
        cls.policy = cls.app.HOST.policy_defaults()
        cls.policy.update(include_uids=[1000], dns_upstream="192.0.2.1", health_domains=["dual.matched.test"])
        config = cls.app.SINGBOX.runtime_config(["*.matched.test", "exact.test"], cls.policy)
        if os.environ.get("V6ONLY_TEST_STACK"):
            config["inbounds"][-1]["stack"] = os.environ["V6ONLY_TEST_STACK"]
        config["log"]["level"] = "debug"
        config["experimental"]["cache_file"]["path"] = str(cls.directory / "cache.db")
        cls.config = cls.directory / "config.json";cls.config.write_text(json.dumps(config))
        cls.stderr = (cls.directory / "backend.log").open("w+")
        cls.backend = None
        rules = cls.app.HOST.nft_config(cls.policy, "v6only_123456abcdef", True)
        guarded_command(["nft", "-f", "-"], input=rules)
        cls.app.HOST.Host().install_uid_rules(cls.policy)
        cls.start_backend()
        cls.kernel_snapshot = cls.app.HOST.Host().kernel_snapshot(cls.policy)

    @classmethod
    def start_backend(cls):
        cls.backend = subprocess.Popen([str(BINARY), "run", "-c", str(cls.config)], stdout=cls.stderr, stderr=cls.stderr)
        for _ in range(50):
            if cls.backend.poll() is not None:
                cls.stderr.flush();cls.stderr.seek(0)
                raise RuntimeError(cls.stderr.read())
            result = cls.client("dns", "dual.matched.test")
            if result["ok"]:
                return
            time.sleep(0.05)
        raise RuntimeError("隔离 TUN 后端未就绪")

    @classmethod
    def tearDownClass(cls):
        if cls.backend and cls.backend.poll() is None:
            cls.backend.terminate()
            cls.backend.wait(timeout=10)
        cls.peer.stdin.write("stop\n");cls.peer.stdin.flush()
        cls.peer.communicate(timeout=5)
        cls.stderr.close()
        cls.temp.cleanup()

    @classmethod
    def client(cls, kind, value):
        result = subprocess.run([sys.executable, "-B", "-c", CLIENT, kind, value, cls.certificate], capture_output=True, text=True, timeout=7)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)

    def counts(self):
        self.peer.stdin.write("counts\n");self.peer.stdin.flush()
        return read_line(self.peer)

    def test_01_dns_redirect_and_matched_ipv6_tcp(self):
        query = self.client("dns", "dual.matched.test")
        self.assertTrue(query["ok"])
        self.assertIn(ipaddress.ip_address(query["address"]), ipaddress.ip_network(self.policy["fake_ipv4"]))
        before = self.counts()
        result = self.client("tcp", query["address"])
        self.assertEqual(result.get("reply"), "ipv6", result)
        self.assertEqual(self.counts()["ipv4"], before["ipv4"])

    def test_02_only_a_fails_without_ipv4_outbound(self):
        query = self.client("dns", "only-a.matched.test")
        before = self.counts()
        self.assertFalse(self.client("tcp", query["address"])["ok"])
        self.assertEqual(self.counts()["ipv4"], before["ipv4"])

    def test_01a_dns_tcp_and_tls_certificate_over_ipv6(self):
        query = self.client("dns_tcp", "dual.matched.test")
        self.assertTrue(query["ok"], query)
        self.assertEqual(self.client("tls", query["address"]).get("reply"), "tls6")
        self.assertEqual(self.client("tls_libc", "dual.matched.test").get("reply"), "tls6")

    def test_03a_exact_wildcard_root_and_similar_domains(self):
        for name in ("matched.test", "child.exact.test", "only-a.abcmatched.test", "only-a.matched.test.evil.test"):
            with self.subTest(name=name):
                query = self.client("dns", name)
                self.assertEqual(self.client("tcp", query["address"]).get("reply"), "ipv4")
        query = self.client("dns", "exact.test")
        self.assertFalse(self.client("tcp", query["address"])["ok"])

    def test_03_unmatched_dual_stack_falls_back_to_ipv4(self):
        query = self.client("dns", "only-a.normal.test")
        self.assertEqual(self.client("tcp", query["address"]).get("reply"), "ipv4")
        self.assertEqual(self.client("tcp", "192.0.2.1").get("reply"), "ipv4")

    def test_04_matched_udp_uses_ipv6(self):
        query = self.client("dns", "udp.matched.test")
        self.assertEqual(self.client("udp", query["address"]).get("reply"), "udp6")

    def test_05_ipv6_route_loss_does_not_fallback(self):
        query = self.client("dns", "loss.matched.test")
        before = self.counts()
        guarded_command(["ip", "-6", "addr", "del", "2001:db8::2/64", "dev", "v6up"])
        try:
            self.assertFalse(self.client("tcp", query["address"])["ok"])
            self.assertEqual(self.counts()["ipv4"], before["ipv4"])
        finally:
            guarded_command(["ip", "-6", "addr", "add", "2001:db8::2/64", "dev", "v6up", "nodad"])
            guarded_command(["ip", "-6", "route", "replace", "default", "via", "2001:db8::1"])

    def test_07_reconcile_rules_and_dynamic_ipv6_address(self):
        guarded_command(["ip", "-6", "rule", "add", "priority", "25423", "from", "2001:db8::/64", "lookup", "47423"])
        try:
            for _ in range(3):
                guarded_command(["ip", "-6", "route", "replace", "table", "47423", "default", "via", "2001:db8::1", "dev", "v6up"])
                query = self.client("dns", "reconcile.matched.test")
                result = self.client("tcp", query["address"])
                if result.get("reply") != "ipv6":
                    self.stderr.flush()
                    diagnostics = (self.directory / "backend.log").read_text()[-6000:]
                    diagnostics += guarded_command(["ip", "-6", "rule", "show"]).stdout
                    diagnostics += guarded_command(["ip", "-6", "route", "get", "2001:db8::1"]).stdout
                    self.fail(str(result) + "\n" + diagnostics)
            guarded_command(["ip", "-6", "addr", "add", "2001:db8::3/64", "dev", "v6up", "nodad"])
            guarded_command(["ip", "-6", "addr", "del", "2001:db8::2/64", "dev", "v6up"])
            query = self.client("dns", "changed.matched.test")
            self.assertEqual(self.client("tcp", query["address"]).get("reply"), "ipv6")
            self.assertEqual(self.counts()["peer_ipv6"], "2001:db8::3")
        finally:
            guarded_command(["ip", "-6", "addr", "replace", "2001:db8::2/64", "dev", "v6up", "nodad"])
            addresses = guarded_command(["ip", "-j", "-6", "addr", "show", "dev", "v6up"]).stdout
            if "2001:db8::3" in addresses:
                guarded_command(["ip", "-6", "addr", "del", "2001:db8::3/64", "dev", "v6up"])
            guarded_command(["ip", "-6", "rule", "del", "priority", "25423", "from", "2001:db8::/64", "lookup", "47423"])

    def test_06_dns_failure_never_falls_back_to_ipv4(self):
        query = self.client("dns", "dns-failure.matched.test")
        before = self.counts()
        self.peer.stdin.write("dns-off\n");self.peer.stdin.flush();read_line(self.peer)
        try:
            self.assertFalse(self.client("tcp", query["address"])["ok"])
            self.assertEqual(self.counts()["ipv4"], before["ipv4"])
        finally:
            self.peer.stdin.write("dns-on\n");self.peer.stdin.flush();read_line(self.peer)

    def test_08_fakeip_mapping_survives_graceful_restart(self):
        cached = self.client("dns", "sticky.matched.test")["address"]
        self.assertEqual(self.client("tcp", cached).get("reply"), "ipv6")
        self.backend.terminate();self.backend.wait(timeout=10)
        self.start_backend()
        self.client("dns", "different.normal.test")
        self.assertEqual(self.client("dns", "sticky.matched.test")["address"], cached)
        self.assertEqual(self.client("tcp", cached).get("reply"), "ipv6")

    def test_09_cached_ipv4_with_visible_sni_is_rejected(self):
        context = ssl.create_default_context(cadata=self.certificate)
        with socket.create_connection(("192.0.2.1", 8444), timeout=3) as stream:
            with context.wrap_socket(stream, server_hostname="dual.matched.test") as tls:
                tls.sendall(b"fixture")
                self.assertEqual(tls.recv(1024), b"tls4")
        before = self.counts()["tls4"]
        self.assertFalse(self.client("tls", "192.0.2.1")["ok"])
        self.assertEqual(self.counts()["tls4"], before)

    def test_10_other_namespace_with_same_uid_is_not_proxied(self):
        process = subprocess.Popen(["unshare", "--net", sys.executable, "-B", str(SELF), "--container"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            info = read_line(process)
            self.assertNotEqual(info["netns"], os.stat('/proc/self/ns/net').st_ino)
            guarded_command(["ip", "link", "add", "podhost", "type", "veth", "peer", "name", "podeth"])
            guarded_command(["ip", "link", "set", "podeth", "netns", str(info["pid"])])
            guarded_command(["ip", "link", "set", "podhost", "up"])
            guarded_command(["ip", "addr", "add", "198.51.100.1/24", "dev", "podhost"])
            guarded_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            self.peer.stdin.write("pod-route\n");self.peer.stdin.flush();read_line(self.peer)
            process.stdin.write("start\n");process.stdin.flush()
            self.assertEqual(read_line(process).get("reply"), "ipv4")
            self.assertEqual(self.counts()["peer_ipv4"], "198.51.100.2")
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)

    def test_11_restart_after_sigkill_restores_new_connections(self):
        self.backend.kill();self.backend.wait(timeout=5)
        self.start_backend()
        query = self.client("dns", "after-crash.matched.test")
        self.assertEqual(self.client("tcp", query["address"]).get("reply"), "ipv6")
        before = self.app.HOST.Host().kernel_snapshot(self.policy)
        self.app.HOST.Host().install_uid_rules(self.policy)
        self.assertEqual(self.app.HOST.Host().kernel_snapshot(self.policy), before)

    def test_99_backend_crash_blocks_selected_ipv4_but_preserves_root(self):
        self.backend.kill();self.backend.wait(timeout=5)
        before = self.counts()
        self.assertFalse(self.client("tcp", "192.0.2.1")["ok"])
        self.assertEqual(self.counts()["ipv4"], before["ipv4"])
        with socket.create_connection(("192.0.2.1", 8443), timeout=3) as connection:
            connection.sendall(b"fixture")
            self.assertEqual(connection.recv(1024), b"ipv4")
        guarded_command(["ip", "-6", "rule", "add", "priority", "25423", "from", "2001:db8::/64", "lookup", "47423"])
        try:
            self.app.HOST.Host().cleanup_kernel(self.policy, self.kernel_snapshot)
        except self.app.HOST.HostError:
            self.fail(json.dumps({"expected": self.kernel_snapshot, "current": self.app.HOST.Host().kernel_snapshot(self.policy)}, ensure_ascii=False, indent=2))
        self.assertFalse(any(self.app.HOST.Host().kernel_snapshot(self.policy).values()))
        self.assertIn("25423", guarded_command(["ip", "-6", "rule", "show"]).stdout)


class NamespaceIntegration(unittest.TestCase):
    def test_isolated_tun_scenarios(self):
        import hashlib
        verified = json.loads((BINARY.parent / "verified.json").read_text())
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), verified["binary_sha256"])
        parent = os.stat("/proc/self/ns/net").st_ino
        environment = dict(os.environ, V6ONLY_PARENT_NETNS=str(parent), PYTHONDONTWRITEBYTECODE="1")
        process = subprocess.Popen(["unshare", "--net", sys.executable, "-B", str(SELF), "--worker"],
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=120)
        finally:
            # 即使测试初始化中途失败，也清理本测试进程组中的后端和服务端。
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                process.wait(timeout=5)
        self.assertEqual(os.stat("/proc/self/ns/net").st_ino, parent)
        (ROOT / ".dev-state/results").mkdir(parents=True, exist_ok=True)
        (ROOT / ".dev-state/results/tun-namespace-details.txt").write_text(stdout + stderr)
        self.assertEqual(process.returncode, 0, stdout + stderr)


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromTestCase(NamespaceIntegration)


if __name__ == "__main__":
    if "--peer" in sys.argv:
        peer()
    elif "--container" in sys.argv:
        container_client()
    elif "--worker" in sys.argv:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WorkerTests))
        sys.exit(0 if result.wasSuccessful() else 1)
    else:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NamespaceIntegration))
        sys.exit(0 if result.wasSuccessful() else 1)

"""dnsmasq 2.91 三实例 DNS 约束模式，不宣称严格出站控制。"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import tempfile

VERSION = "2.91"


class BackendFailure(Exception):
    def __init__(self, message, code=4):
        super().__init__(message)
        self.code = code


def common(port):
    return [f"port={port}", "listen-address=127.0.0.1,::1", "bind-interfaces", "no-resolv", "no-hosts",
            "cache-size=256", "pid-file=", "log-facility=-", "user=root", "group=root"]


def configs(domains, upstream, port=1053):
    try:
        address = ipaddress.ip_address(upstream)
        if address.is_unspecified or address.is_multicast or address.is_link_local or "%" in upstream:
            raise ValueError
    except ValueError:
        raise BackendFailure("DNS 上游必须为可用的单个 IP 地址。", 2)
    if not 1024 <= port <= 65533:
        raise BackendFailure("DNS 端口必须为 1024–65533。", 2)
    exact = {x for x in domains if not x.startswith("*.")}
    wildcard = {x[2:] for x in domains if x.startswith("*.")}
    front = common(port) + [f"server=127.0.0.1#{port + 2}"]
    for base in sorted(exact | wildcard):
        inherited = any(base.endswith("." + parent) for parent in wildcard)
        root_port = port + (1 if base in exact or inherited else 2)
        child_port = port + (1 if base in wildcard or inherited else 2)
        # 带点的前缀通配仅匹配子域；通过独立根域/子域分派保留两种语义。
        front += [f"server=/{base}/127.0.0.1#{root_port}", f"server=/*.{base}/127.0.0.1#{child_port}"]
    filtered = common(port + 1) + [f"server={address}", "filter-A", "filter-rr=64,65"]
    normal = common(port + 2) + [f"server={address}"]
    return {"front": "\n".join(front) + "\n", "filtered": "\n".join(filtered) + "\n", "normal": "\n".join(normal) + "\n"}


def render(domains, revision, upstream, port=1053):
    configuration = configs(domains, upstream, port)
    payload = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
    return {"schema": "v6only.dnsmasq-candidate.v1", "backend": "dnsmasq", "backend_version": VERSION,
            "profile": "dns-constraint", "runtime_verified": False, "source_revision": revision,
            "domains": list(domains), "dns_upstream": str(ipaddress.ip_address(upstream)), "dns_port": port,
            "config_sha256": hashlib.sha256(payload.encode()).hexdigest(), "configs": configuration}


def verify_candidate(candidate, normalize):
    try:
        domains, revision = candidate["domains"], candidate["source_revision"]
        if type(domains) is not list or domains != sorted(set(normalize(x) for x in domains)) or type(revision) is not int or revision < 0:
            raise ValueError
        expected = render(domains, revision, candidate["dns_upstream"], candidate["dns_port"])
        if json.dumps(candidate, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError
        return expected
    except Exception:
        raise BackendFailure("dnsmasq 候选文件损坏或被改写，未执行外部校验器。") from None


def invoke(binary, args):
    try:
        return subprocess.run([str(Path(binary).absolute()), *args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise BackendFailure("dnsmasq 校验超时。")
    except OSError:
        raise BackendFailure("无法执行 dnsmasq，请提供可信的 2.91 二进制。", 3)


def probe(binary):
    result = invoke(binary, ["--version"])
    if result.returncode or not re.search(r"^Dnsmasq version 2\.91\s", result.stdout):
        raise BackendFailure("dnsmasq 版本不兼容，本轮仅接受 2.91。", 3)
    return {"backend": "dnsmasq", "version": VERSION, "runtime_verified": False}


def validate(candidate, binary, normalize):
    candidate = verify_candidate(candidate, normalize)
    information = probe(binary)
    results = {}
    with tempfile.TemporaryDirectory(prefix="v6only-dnsmasq-check-") as directory:
        for name, content in candidate["configs"].items():
            path = Path(directory) / (name + ".conf")
            path.write_text(content)
            result = invoke(binary, ["--test", "--conf-file=" + str(path)])
            if result.returncode:
                raise BackendFailure("dnsmasq 配置校验失败。\n" + result.stdout[:8192])
            results[name] = result.stdout.strip()
    return {**information, "syntax_checked": True, "checker_output": results,
            "说明": "DNS 约束模式，无法阻止缓存 IPv4、独立 DNS 或直接 IP 连接。"}

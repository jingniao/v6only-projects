"""sing-box 1.14.1 candidate configuration and runtime configuration."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import parse_qsl, urlsplit

SINGBOX_VERSION = "1.14.1"
CANDIDATE_SCHEMA = "v6only.singbox-candidate.v1"


class BackendFailure(Exception):
    def __init__(self, message, code=4):
        super().__init__(message)
        self.code = code


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dns_address(value):
    try:
        if "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast or address.is_link_local or getattr(address, "ipv4_mapped", None):
            raise ValueError
        return str(address)
    except (TypeError, ValueError):
        raise BackendFailure("DNS 上游须为单个 IPv4/IPv6 地址，不接受端口、URL、作用域、组播或未指定地址。", 2)


def runtime_dns_server(value):
    """Build a runtime DNS server; offline candidates deliberately remain IP-only."""
    try:
        address = dns_address(value)
        return {"type": "udp", "tag": "upstream", "server": address, "server_port": 53}
    except BackendFailure:
        pass
    try:
        parsed = urlsplit(value)
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or
                parsed.port not in {None, 443} or not parsed.hostname or parsed.path != "/dns-query" or
                len(query) != 1 or query[0][0] != "bootstrap"):
            raise ValueError
        host = parsed.hostname.lower()
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
            raise ValueError
        bootstrap = dns_address(query[0][1])
        return {"type": "https", "tag": "upstream", "server": bootstrap, "server_port": 443,
                "path": "/dns-query", "tls": {"enabled": True, "server_name": host}}
    except (TypeError, ValueError):
        raise BackendFailure("运行 DNS 上游须为单个 IP，或 https://域名/dns-query?bootstrap=单个IP。", 2)


def domain_matcher(domains):
    """Use anchored RE2-compatible expressions for wildcard subdomains only."""
    exact, wildcard = [], []
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    for domain in domains:
        if domain.startswith("*."):
            wildcard.append(r"(?i)^(?:" + label + r"\.)+" + re.escape(domain[2:]) + r"\.?$")
        else:
            exact.append(domain)
    matcher = {}
    if exact:
        matcher["domain"] = exact
    if wildcard:
        matcher["domain_regex"] = wildcard
    return matcher


def render(domains, revision, upstream):
    """Render an offline candidate. It performs no network or filesystem operations."""
    upstream = dns_address(upstream)
    matcher = domain_matcher(domains)
    rules = [{"action": "sniff"}]
    if matcher:
        guard = {"type": "logical", "mode": "and",
                 "rules": [copy.deepcopy(matcher), {"ip_cidr": ["0.0.0.0/0", "::ffff:0:0/96"]}],
                 "action": "reject", "method": "default", "no_drop": True}
        rules.extend([
            copy.deepcopy(guard),
            {**copy.deepcopy(matcher), "action": "resolve", "server": "upstream", "strategy": "ipv6_only"},
            copy.deepcopy(guard),
            {**copy.deepcopy(matcher), "action": "route", "outbound": "strict-ipv6"},
        ])
    rules.append({"action": "resolve", "server": "upstream", "strategy": "prefer_ipv6"})
    config = {
        "log": {"disabled": True},
        "dns": {"servers": [{"type": "udp", "tag": "upstream", "server": upstream, "server_port": 53}],
                "final": "upstream", "strategy": "prefer_ipv6", "reverse_mapping": True},
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "default", "domain_resolver": {"server": "upstream", "strategy": "prefer_ipv6"}},
            {"type": "direct", "tag": "strict-ipv6", "domain_resolver": {"server": "upstream", "strategy": "ipv6_only"}},
        ],
        "route": {"rules": rules, "final": "default"},
    }
    return {"schema": CANDIDATE_SCHEMA, "backend": "singbox", "backend_version": SINGBOX_VERSION,
            "profile": "offline-no-inbounds", "runtime_verified": False,
            "source_revision": revision, "domains": list(domains), "dns_upstream": upstream,
            "config_sha256": hashlib.sha256(canonical(config).encode()).hexdigest(), "config": config}


def verify_candidate(candidate, normalize):
    """Only accept a regenerated offline candidate for the pinned sing-box version."""
    try:
        if not isinstance(candidate, dict):
            raise ValueError
        domains, revision = candidate["domains"], candidate["source_revision"]
        if type(domains) is not list or type(revision) is not int or revision < 0:
            raise ValueError
        if domains != sorted(set(normalize(x) for x in domains)):
            raise ValueError
        expected = render(domains, revision, candidate["dns_upstream"])
        if canonical(candidate) != canonical(expected):
            raise ValueError
        return expected
    except Exception:
        raise BackendFailure("候选文件损坏、版本不兼容或内容已被改写；仅接受本工具生成的无入口候选配置。") from None


def binary_path(value):
    path = Path(value).expanduser().absolute()
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            raise OSError
    except OSError:
        raise BackendFailure("需要通过 --binary 指定可信、可执行的 sing-box 1.14.1 文件。", 3)
    return path


def invoke(binary, args, cwd=None):
    try:
        return subprocess.run([str(binary), *args], cwd=cwd, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              encoding="utf-8", errors="replace", timeout=15, check=False)
    except subprocess.TimeoutExpired:
        raise BackendFailure("sing-box 校验进程超时，未启动网络服务。")
    except OSError:
        raise BackendFailure("无法执行指定的 sing-box 文件，请检查架构与权限。", 3)


def probe(binary):
    binary = binary_path(binary)
    result = invoke(binary, ["version"])
    match = re.search(r"^sing-box version (\S+)$", result.stdout, re.MULTILINE)
    if result.returncode or not match or match.group(1) != SINGBOX_VERSION:
        raise BackendFailure("sing-box 版本不兼容：本轮只接受已核验的 1.14.1 正式版。", 3)
    return {"backend": "singbox", "version": SINGBOX_VERSION, "binary": str(binary),
            "network_probed": False, "runtime_verified": False}


def validate(candidate, binary, normalize):
    candidate = verify_candidate(candidate, normalize)
    information = probe(binary)
    with tempfile.TemporaryDirectory(prefix="v6only-check-") as directory:
        path = Path(directory) / "config.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(canonical(candidate["config"]))
        result = invoke(information["binary"], ["check", "-c", str(path)], cwd=directory)
    if result.returncode:
        raise BackendFailure("sing-box 官方配置校验失败；未应用候选配置。\n" + result.stdout[:8192])
    return {**information, "config_sha256": candidate["config_sha256"], "syntax_checked": True,
            "checker_output": result.stdout[:8192], "network_changed": False,
            "说明": "仅通过配置构造校验；没有入口，不代表 TUN 或 IPv6-only 运行验收通过。"}


def runtime_config(domains, policy):
    """Build the TUN/FakeIP configuration for the transactional lifecycle manager."""
    config = render(domains, 0, "192.0.2.53")["config"]
    config["dns"]["servers"] = [runtime_dns_server(policy["dns_upstream"])]
    config["log"] = {"level": "warn", "timestamp": True}
    config["experimental"] = {"cache_file": {"enabled": True, "path": "/var/lib/v6only/singbox-cache.db", "cache_id": "v6only", "store_fakeip": True}}
    config["dns"]["servers"].append({"type": "fakeip", "tag": "fakeip", "inet4_range": policy["fake_ipv4"], "inet6_range": policy["fake_ipv6"]})
    matcher = domain_matcher(domains)
    config["dns"]["rules"] = ([{**copy.deepcopy(matcher), "query_type": ["HTTPS", "SVCB"], "action": "predefined", "rcode": "NOERROR"}] if matcher else [])
    config["dns"]["rules"].append({"query_type": ["A", "AAAA"], "action": "route", "server": "fakeip"})
    config["inbounds"] = [
        {"type": "direct", "tag": "dns-v4", "listen": "127.0.0.1", "listen_port": policy["dns_port"]},
        {"type": "direct", "tag": "dns-v6", "listen": "::1", "listen_port": policy["dns_port"]},
        {"type": "tun", "tag": "tun", "interface_name": "v6only0", "address": policy["tun_addresses"],
         "auto_route": True, "auto_redirect": False, "strict_route": True, "dns_mode": "disabled",
         "iproute2_table_index": policy["route_table"], "iproute2_rule_index": policy["rule_priority"] + 16,
         "include_uid": policy["include_uids"], "include_interface": ["lo"], "route_exclude_address": policy["management_cidrs"], "stack": "gvisor"},
    ]
    config["route"]["rules"].insert(0, {"inbound": ["dns-v4", "dns-v6"], "action": "hijack-dns"})
    config["route"]["auto_detect_interface"] = True
    return config


def validate_runtime(domains, policy, binary):
    config = runtime_config(domains, policy)
    probe(binary)
    config["log"] = {"disabled": True}
    with tempfile.TemporaryDirectory(prefix="v6only-runtime-check-") as directory:
        config["experimental"]["cache_file"]["path"] = str(Path(directory) / "cache.db")
        path = Path(directory) / "config.json"
        path.write_text(canonical(config), encoding="utf-8")
        path.chmod(0o600)
        result = invoke(binary_path(binary), ["check", "-c", str(path)], cwd=directory)
    if result.returncode:
        raise BackendFailure("TUN 候选配置的官方构造校验失败。\n" + result.stdout[:8192])
    return {"syntax_checked": True, "runtime_verified": False, "checker_output": result.stdout[:8192]}

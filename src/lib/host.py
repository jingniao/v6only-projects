"""宿主机适配层；所有修改都由生命周期事务显式调用。"""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import time
from urllib.parse import parse_qsl, urlsplit


class HostError(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


def table_name(identifier):
    if not re.fullmatch(r"v6only_[a-f0-9]{12}", identifier):
        raise HostError("无效的项目防火墙资源标识。")
    return identifier


def nft_config(policy, table, strict):
    table = table_name(table)
    users = ", ".join(str(x) for x in policy["include_uids"])
    port = policy["dns_port"]
    lines = [f"table inet {table} {{", " chain dns_redirect {", "  type nat hook output priority -100; policy accept;",
             f"  meta skuid {{ {users} }} meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to 127.0.0.1:{port}",
             f"  meta skuid {{ {users} }} meta nfproto ipv6 meta l4proto {{ tcp, udp }} th dport 53 dnat ip6 to [::1]:{port}", " }"]
    if strict:
        lines += [" chain fail_closed {", "  type filter hook output priority -5; policy accept;",
                  '  oifname "lo" accept', '  oifname "v6only0" accept']
        for network in policy["management_cidrs"]:
            if ipaddress.ip_network(network).version == 4:
                lines.append(f"  ip daddr {network} accept")
        lines += [f"  meta skuid {{ {users} }} meta nfproto ipv4 counter reject", " }"]
    lines += ["}"]
    return "\n".join(lines) + "\n"


def policy_defaults():
    return {"include_uids": [], "dns_upstream": None, "dns_port": 1053,
            "tun_addresses": ["172.31.255.1/30", "fdfe:dcba:9876::1/126"],
            "fake_ipv4": "198.18.0.0/15", "fake_ipv6": "fc00::/18",
            "route_table": 47620, "rule_priority": 12000,
            "management_cidrs": [], "health_domains": [], "protect_units": _detect_protect_units()}


def _detect_protect_units():
    """探测实际存在的 DynamicV6 系统单元名。"""
    candidates = ["DynamicV6.service", "dynamicv6.service",
                  "dynamicv6-next-guest.service", "dynamicv6-next.service"]
    found = []
    for name in candidates:
        unit_path = Path("/etc/systemd/system") / name
        if unit_path.exists() or unit_path.is_symlink():
            found.append(name)
    if not found:
        # 回退：使用 systemctl 查询运行中的匹配单元
        import subprocess as _sp
        try:
            result = _sp.run(["systemctl", "list-units", "--type=service", "--no-legend", "--no-pager"],
                             capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                unit = line.split()[0] if line.strip() else ""
                if "dynamicv6" in unit.lower() and unit not in found:
                    found.append(unit)
        except Exception:
            pass
    return found if found else ["DynamicV6.service", "dynamicv6.service"]


def rollback_units(identifier, deadline, entry="/usr/local/sbin/v6only"):
    if not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise HostError("无效的事务标识。")
    unit = "v6only-rollback-" + identifier
    when = datetime.datetime.fromisoformat(deadline).astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        unit + ".service": f"[Unit]\nDescription=v6only 独立事务恢复 {identifier}\n[Service]\nType=oneshot\nExecStart={entry} _recover {identifier}\n",
        unit + ".timer": f"[Unit]\nDescription=v6only 事务确认期限 {identifier}\n[Timer]\nOnCalendar={when}\nOnUnitActiveSec=30s\nPersistent=true\nAccuracySec=1s\nUnit={unit}.service\n[Install]\nWantedBy=timers.target\n",
    }


def validate_policy(policy):
    try:
        if set(policy) != set(policy_defaults()):
            raise ValueError
        uids = policy["include_uids"]
        if not isinstance(uids, list) or not 1 <= len(uids) <= 16 or any(type(x) is not int or not 1000 <= x < 2 ** 31 for x in uids):
            raise ValueError
        if uids != sorted(set(uids)):
            raise ValueError
        try:
            address = ipaddress.ip_address(policy["dns_upstream"])
            if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_loopback or getattr(address, "ipv4_mapped", None):
                raise ValueError
        except ValueError:
            parsed = urlsplit(policy["dns_upstream"])
            query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or
                    parsed.port not in {None, 443} or not parsed.hostname or parsed.path != "/dns-query" or
                    len(query) != 1 or query[0][0] != "bootstrap" or
                    not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", parsed.hostname.lower())):
                raise ValueError
            bootstrap = ipaddress.ip_address(query[0][1])
            if bootstrap.is_unspecified or bootstrap.is_multicast or bootstrap.is_link_local or bootstrap.is_loopback or getattr(bootstrap, "ipv4_mapped", None):
                raise ValueError
        if any(type(policy[key]) is not int for key in ("dns_port", "route_table", "rule_priority")):
            raise ValueError
        if not 1024 <= policy["dns_port"] <= 65533 or not 10000 <= policy["route_table"] <= 2 ** 31 or not 1000 <= policy["rule_priority"] <= 30000:
            raise ValueError
        if len(policy["tun_addresses"]) != 2 or {ipaddress.ip_interface(x).version for x in policy["tun_addresses"]} != {4, 6}:
            raise ValueError
        if ipaddress.ip_network(policy["fake_ipv4"]).version != 4 or ipaddress.ip_network(policy["fake_ipv6"]).version != 6:
            raise ValueError
        for network in policy["management_cidrs"]:
            if str(ipaddress.ip_network(network)) != network or ipaddress.ip_network(network).prefixlen != ipaddress.ip_network(network).max_prefixlen:
                raise ValueError
        if any(not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", unit) for unit in policy["protect_units"]):
            raise ValueError
        if not 1 <= len(policy["health_domains"]) <= 3 or any("*" in name for name in policy["health_domains"]):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise HostError("网络策略无效：必须明确非系统 UID、DNS 上游、健康域名和合法资源范围。", 2)
    return policy


class Host:
    mode = "live"
    # 允许用 V6ONLY_ROOT 覆盖运行时根目录；默认仍是真实根 "/"。
    # 仅用于测试隔离运行时状态（清单状态用 V6ONLY_STATE_DIR）。
    root = Path(os.environ.get("V6ONLY_ROOT", "/"))

    def command(self, args, input=None, check=True, timeout=30):
        try:
            result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise HostError("系统命令无法执行或超时：" + args[0], 4)
        if check and result.returncode:
            raise HostError("系统操作失败：" + args[0] + "（退出码 " + str(result.returncode) + "）。", 4)
        return result

    def inspect(self, policy=None, installed=False, check_routes=True, require_peer_exclusion=True):
        release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                release[key] = value.strip('"')
        missing = [x for x in ("ip", "nft", "systemctl", "systemd-run", "journalctl") if not shutil.which(x)]
        available_uids = sorted(account.pw_uid for account in pwd.getpwall() if 1000 <= account.pw_uid < 65534)
        report = {"mode": self.mode, "distribution": release.get("ID"), "version": release.get("VERSION_ID"),
                  "uid": os.geteuid(), "tun_available": Path("/dev/net/tun").exists(), "missing_tools": missing,
                  "systemd": Path("/run/systemd/system").is_dir(), "network_modified": False,
                  "available_uids": available_uids}
        if not available_uids:
            report["uid_hint"] = ("本机没有 UID≥1000 的非系统用户，无法完成接管前置检查；"
                                  "请先建立专用用户，例如：useradd --uid 1500 --no-create-home --shell /usr/sbin/nologin v6only-run")
        if policy:
            validate_policy(policy)
            if missing:
                return report
            rules4 = json.loads(self.command(["ip", "-j", "rule", "show"]).stdout)
            rules6 = json.loads(self.command(["ip", "-j", "-6", "rule", "show"]).stdout)
            routes = json.loads(self.command(["ip", "-j", "route", "show", "table", "all"]).stdout)
            routes += json.loads(self.command(["ip", "-j", "-6", "route", "show", "table", "all"]).stdout)
            report["rules"] = rules4 + rules6
            report["routes"] = routes
            protected = {0}
            for unit in policy["protect_units"]:
                result = self.command(["systemctl", "show", unit, "--property=User", "--value"], check=False)
                user = result.stdout.strip()
                if result.returncode == 0 and user:
                    try:
                        protected.add(int(user) if user.isdigit() else pwd.getpwnam(user).pw_uid)
                    except KeyError:
                        raise HostError("无法确定管理服务 UID，拒绝自动接管。")
            # 只保留 UID，不记录可能带凭据的进程命令行。
            result = self.command(["ps", "-eo", "uid=,args="], check=False)
            for line in result.stdout.splitlines():
                if "dynamicv6" in line.lower():
                    try:
                        protected.add(int(line.strip().split(None, 1)[0]))
                    except ValueError:
                        pass
            if set(policy["include_uids"]) & protected:
                raise HostError("接管 UID 与 SSH/root 或 DynamicV6 管理用户重叠。")
            for uid in policy["include_uids"]:
                try:
                    pwd.getpwuid(uid)
                except KeyError:
                    raise HostError(f"接管 UID {uid} 对应的本机用户不存在；请先建立专用非系统用户，"
                                    f"例如：useradd --uid {uid} --no-create-home --shell /usr/sbin/nologin v6only-run", 3)
            if not installed and check_routes:
                priority = policy["rule_priority"]
                for rule in report["rules"]:
                    if str(rule.get("table")) == str(policy["route_table"]) or priority <= rule.get("priority", -1) <= priority + 100:
                        raise HostError("项目策略规则或路由表与现有资源冲突。")
                    # 含自定义策略的主机需要明确分析优先级，不能仅比较表号。
                    if 0 < rule.get("priority", 32766) < priority:
                        raise HostError("既有策略规则先于项目接管规则，需完成选路适配后才能接管。")
                reserved = [ipaddress.ip_interface(x).network for x in policy["tun_addresses"]]
                reserved += [ipaddress.ip_network(policy["fake_ipv4"]), ipaddress.ip_network(policy["fake_ipv6"])]
                for route in routes:
                    destination = route.get("dst", "default")
                    if destination == "default":
                        continue
                    try:
                        network = ipaddress.ip_network(destination, strict=False)
                    except ValueError:
                        continue
                    if any(network.version == own.version and network.overlaps(own) for own in reserved):
                        raise HostError("TUN/FakeIP 地址范围与现有路由重叠。")
                links = json.loads(self.command(["ip", "-j", "link", "show"]).stdout)
                if any(x.get("ifname") == "v6only0" for x in links):
                    raise HostError("v6only0 接口已存在，无法证明归属。")
            peer = os.environ.get("SSH_CONNECTION", "").split()
            report["ssh_peer"] = peer[0] if peer else None
            report["ssh_route"] = self.route(peer[0]) if peer else None
            if peer and require_peer_exclusion:
                peer_address = ipaddress.ip_address(peer[0])
                if not any(peer_address in ipaddress.ip_network(x) for x in policy["management_cidrs"]):
                    raise HostError("当前 SSH 对端未加入管理路径排除清单。")
            report["protected_uids"] = sorted(protected)
        return report

    def check_ports(self, policy, backend, before):
        requested = {policy["dns_port"] + offset for offset in range(3 if backend == "dnsmasq" else 1)}
        owned = set()
        if before.get("enabled"):
            owned = {before["policy"]["dns_port"] + offset for offset in range(3 if before["backend"] == "dnsmasq" else 1)}
        for port in requested - owned:
            for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                    try:
                        with socket.socket(family, kind) as stream:
                            stream.bind((address, port))
                    except OSError:
                        raise HostError("项目 DNS 端口已被占用或回环地址不可用，拒绝覆盖现有服务。")

    def namespace_path(self):
        machine = (self.root / "etc/machine-id").read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{32}", machine):
            raise HostError("machine-id 无效，无法确定专属日志目录。")
        path = self.root / "var/log/journal" / (machine + ".v6only")
        for parent in [path, *path.parents]:
            if parent.is_symlink():
                raise HostError("专属日志路径包含符号链接。", 5)
        return path

    def stop_namespace(self):
        names = ["systemd-journald-varlink@v6only.socket", "systemd-journald@v6only.socket", "systemd-journald-sync@v6only.service", "systemd-journald@v6only.service"]
        for name in names:
            loaded = self.command(["systemctl", "show", name, "--property=LoadState", "--value"], check=False)
            if loaded.returncode:
                raise HostError("无法确认专属日志服务状态。", 5)
            if loaded.stdout.strip() == "loaded":
                self.command(["systemctl", "stop", name])
                if self.active(name):
                    raise HostError("专属日志服务未停止，保留日志。", 5)

    def remove_namespace(self):
        path = self.namespace_path()
        if not path.exists():
            return
        self.stop_namespace()
        for item in path.iterdir():
            if (item.is_symlink() or not item.is_file() or
                    not re.fullmatch(r"(?:system|user-\d+)(?:@[0-9a-f-]+)?\.journal~?|fss", item.name)):
                raise HostError("专属 journal 目录含未知文件，停止清理。", 5)
        shutil.rmtree(path)

    def require_supported(self, report, require_tun=True):
        supported = {"debian": {"12", "13"}, "ubuntu": {"22.04", "24.04"}}
        if report["uid"] != 0 or not report["systemd"]:
            raise HostError("实际生命周期操作需要 root 和运行中的 systemd。")
        if report["version"] not in supported.get(report["distribution"], set()):
            raise HostError("当前系统不在实验支持范围（Debian 12/13、Ubuntu 22.04/24.04）。")
        if require_tun and not report["tun_available"]:
            raise HostError("/dev/net/tun 不可用。")
        if report["missing_tools"]:
            raise HostError("缺少依赖：" + ", ".join(report["missing_tools"]))

    def route(self, address, uid=0):
        family = "-6" if ipaddress.ip_address(address).version == 6 else "-4"
        result = self.command(["ip", "-j", family, "route", "get", address, "uid", str(uid)])
        records = json.loads(result.stdout)
        return {k: records[0].get(k) for k in ("dev", "gateway", "prefsrc", "table")}

    def service(self, name, operation):
        if not re.fullmatch(r"v6only-[A-Za-z0-9-]+\.(service|timer)", name):
            raise HostError("拒绝操作非本项目服务。")
        self.command(["systemctl", operation, name])

    def reload(self):
        self.command(["systemctl", "daemon-reload"])

    def active(self, name):
        result = self.command(["systemctl", "is-active", "--quiet", name], check=False)
        if result.returncode not in {0, 3, 4}:
            raise HostError("无法确认服务状态，不能视为已经停用。", 4)
        return result.returncode == 0

    def nft_snapshot(self, name):
        name = table_name(name)
        result = self.command(["nft", "-j", "list", "table", "inet", name], check=False)
        if result.returncode:
            if "No such file" in result.stderr or "does not exist" in result.stderr:
                return None
            raise HostError("无法读取项目 nftables 表，不能确认资源归属。")
        value = json.loads(result.stdout)
        # handle 会在原子重建时变化，计数器随流量变化；不用于用户修改判断。
        def normalize(obj):
            if isinstance(obj, dict):
                return {k: normalize(v) for k, v in obj.items() if k not in {"handle", "metainfo", "packets", "bytes"}}
            if isinstance(obj, list):
                return [normalize(x) for x in obj if not (isinstance(x, dict) and "metainfo" in x)]
            return obj
        return normalize(value)

    def nft_replace(self, name, content):
        name = table_name(name)
        present = self.nft_snapshot(name)
        script = (f"delete table inet {name}\n" if present is not None else "") + (content or "")
        if script:
            self.command(["nft", "-c", "-f", "-"], input=script)
            self.command(["nft", "-f", "-"], input=script)
        return self.nft_snapshot(name)

    def kernel_snapshot(self, policy):
        result = {"rules": [], "routes": [], "addresses": []}
        for family in ("-4", "-6"):
            rules = json.loads(self.command(["ip", "-j", family, "rule", "show"]).stdout)
            for rule in rules:
                if str(rule.get("table")) == str(policy["route_table"]) or policy["rule_priority"] <= rule.get("priority", -1) <= policy["rule_priority"] + 100:
                    # 接口退出后内核会添加 detached 标记，这不是策略被用户改写。
                    stable = {key: value for key, value in rule.items() if key not in {"iif_detached", "oif_detached"}}
                    result["rules"].append({"family": family, "rule": stable})
            routes = self.command(["ip", "-j", family, "route", "show", "table", str(policy["route_table"])], check=False)
            if routes.returncode == 0:
                result["routes"] += [{"family": family, "route": route} for route in json.loads(routes.stdout)]
            elif "FIB table does not exist" not in routes.stderr:
                raise HostError("无法读取项目路由表。", 4)
        address = self.command(["ip", "-j", "address", "show", "dev", "v6only0"], check=False)
        if address.returncode == 0:
            for interface in json.loads(address.stdout):
                result["addresses"] += [{key: value for key, value in item.items() if key in {"family", "local", "prefixlen", "scope"}}
                                         for item in interface.get("addr_info", []) if item.get("scope") == "global"]
        return result

    def install_uid_rules(self, policy):
        """在 TUN 自带规则前按 UID 查专属表，避免主表的具体 IPv4 路由绕过接管。"""
        existing = self.kernel_snapshot(policy)["rules"]
        for family in ("-4", "-6"):
            for uid in policy["include_uids"]:
                networks = [network for network in policy["management_cidrs"] if ipaddress.ip_network(network).version == (4 if family == "-4" else 6)]
                for network in [*networks, None]:
                    priority = policy["rule_priority"] + (0 if network else 1)
                    table = "main" if network else str(policy["route_table"])
                    found = False
                    for item in existing:
                        rule = item["rule"]
                        uidrange = rule.get("uidrange")
                        uid_matches = (uidrange == f"{uid}-{uid}" or uidrange == {"start": uid, "end": uid}
                                       or (rule.get("uid_start") == uid and rule.get("uid_end") == uid))
                        destination = rule.get("dst")
                        if destination and destination != "all":
                            destination = str(ipaddress.ip_network(destination, strict=False))
                        else:
                            destination = None
                        if item["family"] == family and rule.get("priority") == priority and str(rule.get("table")) == table and uid_matches and destination == network:
                            found = True
                            break
                    if found:
                        continue
                    args = ["ip", family, "rule", "add", "priority", str(priority), "uidrange", f"{uid}-{uid}"]
                    if network:
                        args += ["to", network]
                    args += ["table", table]
                    self.command(args)

    def _is_project_rule(self, rule_item, policy):
        """判断一条 ip rule 是否属于本项目：TUN auto_route 规则或 UID 接管规则。

        只认可证明归属的资源，避免把用户在同一优先级区间新增的无关规则当成项目资源。
        """
        rule = rule_item["rule"]
        pri = rule.get("priority", -1)
        # sing-box auto_route 规则：指向项目专属路由表
        if str(rule.get("table", "")) == str(policy["route_table"]):
            return True
        # 本项目 install_uid_rules 安装的 UID 规则：优先级在保留范围且 UID 属于接管清单
        if policy["rule_priority"] <= pri <= policy["rule_priority"] + 100:
            ranges = []
            start, end = rule.get("uid_start"), rule.get("uid_end")
            if isinstance(start, int) and isinstance(end, int):
                ranges.append((start, end))
            uidrange = rule.get("uidrange")
            if isinstance(uidrange, str) and "-" in uidrange:
                try:
                    parts = uidrange.split("-")
                    ranges.append((int(parts[0]), int(parts[-1])))
                except ValueError:
                    pass
            for low, high in ranges:
                if any(low <= uid <= high for uid in policy["include_uids"]):
                    return True
        return False

    def _is_project_route(self, route_item, policy):
        """项目路由表中的路由均视为本项目资源。"""
        return True  # kernel_snapshot 已按 route_table 过滤

    def _is_project_address(self, addr_item, policy):
        """v6only0 上的全局地址均视为本项目资源。"""
        return True  # kernel_snapshot 已按 dev=v6only0 过滤

    def kernel_conflicts(self, policy, expected):
        """检测项目内核资源范围内是否存在非本项目的外部修改。"""
        if expected is None:
            return False
        current = self.kernel_snapshot(policy)
        for item in current["rules"]:
            if item not in expected["rules"] and not self._is_project_rule(item, policy):
                return True
        for item in current["routes"]:
            if item not in expected["routes"] and not self._is_project_route(item, policy):
                return True
        for item in current["addresses"]:
            if item not in expected["addresses"] and not self._is_project_address(item, policy):
                return True
        return False

    def cleanup_kernel(self, policy, expected):
        current = self.kernel_snapshot(policy)
        if any(current.values()) and expected is None:
            # B1-fix: 后端重启后快照可能为 None；按实际采集的内核资源清理。
            expected = {"rules": [], "routes": [], "addresses": []}
        if expected is not None:
            # B2-fix: 与 kernel_conflicts 一致地按归属判断。早于 auto_route 落地采集的快照会缺项，
            # 项目自身随后新增的规则/路由不能因此被当成用户后续修改而永久拒绝清理。
            foreign = [item for item in current["rules"]
                       if item not in expected["rules"] and not self._is_project_rule(item, policy)]
            foreign += [item for item in current["routes"]
                        if item not in expected["routes"] and not self._is_project_route(item, policy)]
            if foreign:
                raise HostError("残留内核资源包含用户后续修改，停止自动删除。", 5)
        if current["addresses"]:
            # 后端应先停止，文件描述符释放后 TUN 应消失；不盲目删除仍被进程使用的接口。
            raise HostError("项目 TUN 接口仍存在，不能确认服务已释放资源。", 5)
        for item in current["rules"]:
            rule = item["rule"]
            args = ["ip", item["family"], "rule", "del", "priority", str(rule["priority"])]
            if "table" in rule:
                args += ["table", str(rule["table"])]
            self.command(args)
        for item in current["routes"]:
            route = item["route"]
            args = ["ip", item["family"], "route", "del", "table", str(policy["route_table"]), route.get("dst", "default")]
            if "dev" in route:
                args += ["dev", route["dev"]]
            self.command(args)
        if any(self.kernel_snapshot(policy).values()):
            raise HostError("项目内核资源未完全恢复。", 5)

    def wait_ready(self, state, deadline):
        until = min(time.monotonic() + 10, time.monotonic() + max(0, (datetime.datetime.fromisoformat(deadline) - datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
        while time.monotonic() < until:
            services = all(self.active(name) for name in state["services"])
            try:
                with socket.create_connection(("127.0.0.1", state["policy"]["dns_port"]), timeout=0.2):
                    if services:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise HostError("后端在期限内未就绪。", 4)

    def wait_settled(self, policy, deadline=None, quiet=1.5, limit=20.0, interval=0.2):
        """B2-fix: 等 sing-box auto_route 的规则/路由落地并稳定后再采集快照。

        wait_ready 只确认 systemd 单元活跃且 DNS 端口可连；此时 auto_route 生成的
        专属路由表条目与 ip rule 可能尚未出现。过早采集的快照会缺项，之后
        uninstall/enable 会把项目自身的自动规则误判为外部修改（exit 5）。
        """
        budget = limit
        if deadline:
            try:
                remaining = (datetime.datetime.fromisoformat(deadline)
                             - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
                budget = min(limit, max(0.0, remaining))
            except (TypeError, ValueError):
                budget = limit
        until = time.monotonic() + budget
        previous = None
        changed = time.monotonic()
        while time.monotonic() < until:
            current = self.kernel_snapshot(policy)
            if current != previous:
                previous, changed = current, time.monotonic()
            elif time.monotonic() - changed >= quiet:
                return True
            time.sleep(interval)
        return False

    def arm(self, identifier, deadline, entry="/usr/local/sbin/v6only"):
        # 永久 timer 使用绝对 UTC 截止时间，SSH 断开或重启不会丢失期限。
        unit = "v6only-rollback-" + identifier
        directory = self.root / "etc/systemd/system"
        files = rollback_units(identifier, deadline, entry)
        manifest = self.root / "var/lib/v6only/transactions" / identifier / "timer-manifest.json"
        manifest.write_text(json.dumps({name: hashlib.sha256(content.encode()).hexdigest() for name, content in files.items()}))
        manifest.chmod(0o600)
        for name, content in files.items():
            path = directory / name
            with path.open("x") as stream:
                stream.write(content)
            path.chmod(0o600)
        self.reload()
        self.command(["systemctl", "enable", "--now", unit + ".timer"])
        if not self.active(unit + ".timer"):
            raise HostError("独立回滚定时器未进入运行状态。", 4)

    def disarm(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise HostError("无效事务标识。")
        unit = "v6only-rollback-" + identifier
        manifest = self.root / "var/lib/v6only/transactions" / identifier / "timer-manifest.json"
        fingerprints = json.loads(manifest.read_text()) if manifest.exists() else {}
        for extension in (".timer", ".service"):
            path = self.root / "etc/systemd/system" / (unit + extension)
            if path.exists() and (path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != fingerprints.get(path.name)):
                raise HostError("当前事务的回滚单元被外部修改，未删除。", 5)
        self.command(["systemctl", "disable", "--now", unit + ".timer"], check=False)
        if self.active(unit + ".timer"):
            raise HostError("无法停止当前事务定时器，保留其文件。", 5)
        # 不停止当前可能正在执行的恢复服务，只清除本事务定时器文件。
        for extension in (".timer", ".service"):
            path = self.root / "etc/systemd/system" / (unit + extension)
            if path.exists() and not path.is_symlink():
                path.unlink()
        self.reload()

    def health(self, state, before_report=None, deadline=None):
        services = state.get("services", []) if state.get("enabled") else []
        results = {"services": all(self.active(name) for name in services), "mode": self.mode}
        if state.get("enabled"):
            results["nft"] = self.nft_snapshot(state["nft_table"]) is not None
            if state["backend"] == "singbox":
                results["route"] = all(self.route("192.0.2.1", uid).get("dev") == "v6only0" for uid in state["policy"]["include_uids"])
            probes = []
            for domain in state["policy"]["health_domains"]:
                remaining = ((datetime.datetime.fromisoformat(deadline) - datetime.datetime.now(datetime.timezone.utc)).total_seconds() if deadline else 25)
                if remaining <= 1:
                    probes.append(False)
                    break
                result = self.command(["/usr/local/sbin/v6only", "_netcheck", domain, "--uid", str(state["policy"]["include_uids"][0])], check=False, timeout=min(25, remaining))
                try:
                    payload = json.loads(result.stdout)
                except ValueError:
                    payload = {}
                probes.append(result.returncode == 0 and payload.get("ipv6_available") is True)
            results["dns_tcp_tls"] = bool(probes) and all(probes)
        else:
            results["services"] = not any(self.active(name) for name in state.get("services", []))
            if state.get("nft_table"):
                results["nft_removed"] = self.nft_snapshot(state["nft_table"]) is None
        if before_report and before_report.get("ssh_route"):
            peer = before_report.get("ssh_peer")
            current = self.route(peer) if peer else {}
            # 独立 systemd 恢复任务没有 SSH_CONNECTION；使用快照中的对端，允许动态源地址更新。
            results["ssh_route"] = bool(peer) and all(current.get(key) == before_report["ssh_route"].get(key) for key in ("dev", "gateway", "table"))
        results["ok"] = all(value for key, value in results.items() if key != "mode")
        return results


class SandboxHost(Host):
    """仅供测试的内存服务与防火墙，不调用 systemctl、ip 或 nft。"""
    mode = "simulation"

    def __init__(self, root):
        self.root = Path(root)
        self.running = set()
        self.tables = {}
        self.timers = {}
        self.events = []
        self.fail = None

    def inspect(self, policy=None, installed=False, check_routes=True, require_peer_exclusion=True):
        if policy:
            validate_policy(policy)
        return {"mode": self.mode, "distribution": "debian", "version": "13", "uid": 0,
                "tun_available": True, "missing_tools": [], "systemd": True, "ssh_route": None}

    def check_ports(self, policy, backend, before):
        self.events.append(("check_ports", backend))

    def namespace_path(self):
        return self.root / "var/log/journal/simulation.v6only"

    def stop_namespace(self):
        self.events.append(("stop_namespace",))

    def remove_namespace(self):
        self.events.append(("remove_namespace",))
        path = self.namespace_path()
        if path.exists():
            for item in path.iterdir():
                if item.is_symlink() or not item.is_file() or not item.name.endswith(".journal"):
                    raise HostError("模拟 journal 中含未知文件", 5)
            shutil.rmtree(path)

    def command(self, *args, **kwargs):
        raise AssertionError("模拟器不得执行真实系统命令")

    def service(self, name, operation):
        self.events.append((operation, name))
        if self.fail == operation + "_once":
            self.fail = None
            raise HostError("测试注入单次服务故障", 4)
        if self.fail == operation:
            raise HostError("测试注入服务故障", 4)
        if operation in {"start", "restart", "enable"}:
            self.running.add(name)
        elif operation in {"stop", "disable"}:
            self.running.discard(name)

    def reload(self):
        self.events.append(("reload",))

    def active(self, name):
        return name in self.running

    def nft_snapshot(self, name):
        return self.tables.get(name)

    def kernel_snapshot(self, policy):
        return {"rules": [], "routes": [], "addresses": []}

    def install_uid_rules(self, policy):
        self.events.append(("install_uid_rules",))

    def cleanup_kernel(self, policy, expected):
        self.events.append(("cleanup_kernel",))

    def wait_ready(self, state, deadline):
        self.events.append(("wait_ready",))

    def wait_settled(self, policy, deadline=None, **kwargs):
        self.events.append(("wait_settled",))
        return True

    def nft_replace(self, name, content):
        self.events.append(("nft", name))
        if self.fail == "nft":
            raise HostError("测试注入防火墙失败", 4)
        if content is None:
            self.tables.pop(name, None)
        else:
            self.tables[name] = {"content": content}
        return self.nft_snapshot(name)

    def arm(self, identifier, deadline, entry="/usr/local/sbin/v6only"):
        self.events.append(("arm", identifier))
        if self.fail == "arm":
            raise HostError("测试注入回滚调度失败", 4)
        self.timers[identifier] = deadline

    def disarm(self, identifier):
        self.events.append(("disarm", identifier))
        self.timers.pop(identifier, None)

    def health(self, state, before_report=None, deadline=None):
        if self.fail == "health_once":
            self.fail = None
            return {"ok": False, "mode": self.mode, "network_verified": False}
        return {"ok": self.fail != "health", "mode": self.mode, "network_verified": False}

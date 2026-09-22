#!/usr/bin/env python3
"""v6only：本地清单与候选配置管理，不操作宿主机网络。"""
import argparse
import contextlib
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

# BEGIN BACKEND LOADER
def load_singbox():
    import importlib.util
    path = Path(__file__).resolve().parents[1] / "backends/singbox.py"
    spec = importlib.util.spec_from_file_location("v6only_singbox", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SINGBOX = load_singbox()
def load_local(name, relative):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DNSMASQ = load_local("v6only_dnsmasq", "backends/dnsmasq.py")
TRANSACTIONS = load_local("v6only_transactions", "lib/transactions.py")
HOST = load_local("v6only_host", "lib/host.py")
OBSERVABILITY = load_local("v6only_observability", "lib/observability.py")
RUNTIME = load_local("v6only_runtime", "lib/runtime.py")
# END BACKEND LOADER

VERSION = "0.3.0-dev"
MAX_INPUT = 4 * 1024 * 1024
MAX_EVENTS = 200
UNIMPLEMENTED = set()
LIFECYCLE = {"install", "update", "reinstall", "disable", "enable", "uninstall"}


class Failure(Exception):
    def __init__(self, message, code=4):
        super().__init__(message)
        self.code = code


def normalize(value):
    """域名验证不执行外部命令；通配规则与根域分别保留。"""
    if not value.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise Failure("域名必须为无空白和控制字符的 ASCII 文本。", 2)
    value = value.lower()
    if value.endswith("."):
        value = value[:-1]
    wildcard = value.startswith("*.")
    domain = value[2:] if wildcard else value
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise Failure("不接受 IP 地址。", 2)
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or all(x.isdigit() for x in labels):
        raise Failure("需要合法的完整域名，长度不超过 253 字节。", 2)
    for label in labels:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise Failure("域名标签非法：不接受 URL、端口、路径或非前缀通配符。", 2)
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                if decoded.isascii() or decoded.encode("idna").decode("ascii") != label:
                    raise ValueError
            except (UnicodeError, ValueError):
                raise Failure("punycode 标签无效或不受当前 IDNA 校验器支持。", 2)
    return ("*." if wildcard else "") + domain


def matches(rule, host):
    host = normalize(host)
    if host.startswith("*."):
        raise Failure("匹配目标必须是精确域名。", 2)
    rule = normalize(rule)
    return host.endswith(rule[1:]) if rule.startswith("*.") else host == rule


def parse_domains(content):
    result = set()
    # 允许文本文件 CRLF，其他控制字符不可借助 splitlines 被吞掉。
    for number, raw in enumerate(content.split("\n"), 1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in raw):
            raise Failure(f"第 {number} 行包含控制字符。", 2)
        line = raw.strip(" \t")
        if not line or line.startswith("#"):
            continue
        line = re.split(r"[ \t]+#", line, maxsplit=1)[0].rstrip(" \t")
        try:
            result.add(normalize(line))
        except Failure as exc:
            raise Failure(f"第 {number} 行：{exc}", 2)
    return sorted(result)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def empty_state():
    return {"schema": 1, "revision": 0, "domains": [], "events": []}


def require(condition):
    # 不能用 assert 校验持久化输入：Python 优化模式会移除断言。
    if not condition:
        raise ValueError("无效状态结构")


def safe_path(path):
    """拒绝已有符号链接路径，防止常见的误写；目录必须由可信用户控制。"""
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise Failure("路径包含符号链接，已拒绝访问。", 3)
    return path


def read_text(path):
    with open(path, "rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise Failure("输入文件超过 4 MiB 限制。", 2)
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise Failure("输入文件必须是 UTF-8 文本。", 2)


class Store:
    def __init__(self, path):
        self.root = safe_path(path)
        self.path = self.root / "state.json"

    def check_directory(self):
        safe_path(self.root)
        if self.root.exists():
            info = self.root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise Failure("数据目录必须由当前用户拥有且权限为 0700；请指定独立目录。", 3)

    def read(self):
        self.check_directory()
        safe_path(self.path)
        if not self.path.exists():
            return empty_state()
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Failure("状态文件必须为当前用户拥有的私有普通文件（0600）。", 3)
        try:
            data = json.loads(read_text(self.path))
            require(type(data) is dict and type(data["schema"]) is int and data["schema"] == 1)
            require(type(data["revision"]) is int and data["revision"] >= 0)
            require(type(data["domains"]) is list)
            require(data["domains"] == sorted(set(normalize(x) for x in data["domains"])))
            require(type(data["events"]) is list and len(data["events"]) == min(data["revision"], MAX_EVENTS))
            previous = 0
            for event in data["events"]:
                require(type(event) is dict)
                require(type(event["revision"]) is int and previous < event["revision"] <= data["revision"])
                require(previous == 0 or event["revision"] == previous + 1)
                previous = event["revision"]
                require(event["result"] == "成功" and event["action"] in {"add", "remove", "import"})
                require(type(event["uid"]) is int and type(event["time"]) is str)
                require(event["transaction"] is None)
                for key in ("added", "removed"):
                    require(type(event[key]) is list)
                    require(all(normalize(x) == x for x in event[key]))
            require(previous == data["revision"])
            return data
        except (ValueError, KeyError, TypeError, Failure, AttributeError, RecursionError):
            raise Failure("本地状态损坏或版本不兼容；未覆盖原文件。")

    @contextlib.contextmanager
    def locked(self):
        self.check_directory()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.check_directory()
        lock = safe_path(self.root / "write.lock")
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def write(self, data):
        payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if len(payload.encode()) > MAX_INPUT:
            raise Failure("本地状态达到 4 MiB 上限；未提交修改。")
        safe_path(self.path)
        atomic_write(self.path, payload, replace=True)


def atomic_write(path, text, replace=False):
    path = safe_path(path)
    if not path.parent.is_dir():
        raise Failure("目标父目录不存在。", 3)
    fd, temporary = tempfile.mkstemp(prefix=".v6only-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            # 硬链接创建具有排他性，导出不得覆盖现有文件。
            os.link(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def preview(data):
    return {
        "格式": "v6only 后端无关规则预览 v1（不可直接交给 sing-box/dnsmasq）",
        "待应用修订": data["revision"],
        "规则": [{"类型": "仅子域" if x.startswith("*.") else "精确",
                  "域名": x[2:] if x.startswith("*.") else x,
                  "策略": "IPv6-only；失败不回退 IPv4"} for x in data["domains"]],
        "未命中策略": "接管且可识别的域名优先 IPv6，允许 IPv4 回退",
        "保障范围": "被接管、能够识别域名并命中规则的连接",
        "部署状态": "这是待应用规则预览，不执行网络变更；实际运行状态请使用 status 查看",
        "后续步骤": ["生成固定版本候选并运行官方校验器", "准备独立回滚", "在指定范围临时应用", "确认提交或到期恢复"],
    }


class ChineseParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self.add_argument("-h", "--help", action="help", help="显示帮助并退出")
        self._positionals.title = "位置参数"
        self._optionals.title = "选项"

    def format_help(self):
        return super().format_help().replace("usage:", "用法:")

    def error(self, message):
        # argparse 原消息可能包含带凭据 URL，避免回显用户输入。
        raise Failure("参数错误：存在未知选项、缺失参数或无效取值；请执行 v6only help。", 2)


def parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="仅预览，不写文件或审计")
    common.add_argument("--state-dir", default=argparse.SUPPRESS, help="开发数据目录（0700）")
    p = ChineseParser(prog="v6only", description="v6only 中文 Linux 管理工具（实验开发版，目标部署尚待验收）", parents=[common])
    sub = p.add_subparsers(dest="command", title="命令")
    for name, description in {
        "help": "显示中文帮助（可选：子命令名）", "version": "显示版本", "list": "查看待应用清单",
        "apply": "事务化应用；需要显式授权网络变更", "status": "查看清单与运行状态",
        "check": "检查本地数据、归属及已安装服务健康", "doctor": "只读报告系统环境与前置条件",
        "history": "查看清单和运行变更历史", "logs": "查看审计、健康或服务日志",
    }.items():
        q = sub.add_parser(name, help=description, parents=[common])
        if name == "apply":
            runtime_options(q)
        if name == "help":
            all_subcommands = ["add", "remove", "import", "export", "list", "apply", "status", "check", "doctor", "history", "logs", "install", "update", "reinstall", "disable", "enable", "uninstall", "confirm", "rollback", "purge", "test", "config", "backend", "version"]
            q.add_argument("subcommand", nargs="?", choices=all_subcommands, help="可选的子命令名")
        if name == "logs":
            q.add_argument("kind", nargs="?", choices=["audit", "changes", "health", "service"], default="audit")
            q.add_argument("--limit", type=int, default=100)
    for name in ("add", "remove"):
        q = sub.add_parser(name, help="添加规则" if name == "add" else "删除规则", parents=[common])
        q.add_argument("domains", nargs="+", help="精确域名或带引号的 '*.example.com'")
    for name in ("import", "export"):
        q = sub.add_parser(name, help="合并导入清单" if name == "import" else "导出到新文件", parents=[common])
        q.add_argument("file", help="UTF-8 文件路径")
    for name in sorted(LIFECYCLE | {"confirm", "rollback", "purge", "test"}):
        descriptions = {"install": "事务化安装与临时启用", "update": "升级到已验证的稳定版", "reinstall": "事务化重装",
                        "disable": "解除接管与严格限制", "enable": "重新启用已应用配置", "uninstall": "恢复网络后移除运行组件",
                        "confirm": "确认当前事务并取消其回滚任务", "rollback": "恢复当前事务", "purge": "卸载验证后清理项目数据",
                        "test": "执行域名 DNS 与 IPv6 TCP/TLS 检查"}
        q = sub.add_parser(name, help=descriptions[name], parents=[common])
        if name in LIFECYCLE:
            runtime_options(q)
        if name == "install":
            q.add_argument("--backend", choices=["singbox", "dnsmasq"], default="singbox")
        if name in {"confirm", "rollback"}:
            q.add_argument("--transaction", help="唯一事务标识；默认选择当前事务")
        if name == "rollback":
            q.add_argument("--accept-network-change", action="store_true")
        if name == "purge":
            q.add_argument("--keep-logs", action="store_true")
            q.add_argument("--remove-entry", action="store_true", help="清理时同时删除未被改动的管理入口")
            q.add_argument("--yes", action="store_true", help="确认清除本项目数据")
        if name == "test":
            q.add_argument("domain")
    q = sub.add_parser("backend", help="后端检查与事务化切换", parents=[common])
    nested = q.add_subparsers(dest="operation", required=True)
    use = nested.add_parser("use", parents=[common])
    use.add_argument("backend", choices=["singbox", "dnsmasq"])
    runtime_options(use)
    probe = nested.add_parser("probe", help="只读检查指定的后端版本", parents=[common])
    probe.add_argument("backend", choices=["singbox", "dnsmasq"])
    probe.add_argument("--binary", required=True, help="可信后端可执行文件路径")
    q = sub.add_parser("config", help="生成与静态校验独立后端候选", parents=[common])
    config_sub = q.add_subparsers(dest="operation", required=True)
    render = config_sub.add_parser("render", help="生成候选，不应用", parents=[common])
    render.add_argument("--backend", choices=["singbox", "dnsmasq"], default="singbox")
    render.add_argument("--dns-server", required=True, help="明确指定 DNS 上游 IP；生成时不查询")
    render.add_argument("--output", help="写入新候选文件；默认输出到终端")
    validate = config_sub.add_parser("validate", help="执行本地官方配置校验", parents=[common])
    validate.add_argument("file", help="本工具生成的候选文件")
    validate.add_argument("--binary", required=True, help="可信的对应版本后端可执行文件路径")
    recover = sub.add_parser("_recover", help="独立定时恢复内部入口", parents=[common])
    recover.add_argument("transaction")
    sub.add_parser("_guard", help="systemd 故障保护内部入口", parents=[common])
    netcheck = sub.add_parser("_netcheck", help="有期限的网络诊断内部入口", parents=[common])
    netcheck.add_argument("domain")
    netcheck.add_argument("--uid", type=int)
    return p


def runtime_options(q):
    q.add_argument("--accept-network-change", action="store_true", help="明确授权实际系统和网络变更")
    q.add_argument("--accept-broad-ipv4-block", action="store_true", help="确认故障保护可能阻断选定用户的更多 IPv4 流量")
    q.add_argument("--accept-dns-downgrade", action="store_true", help="确认备用后端只有 DNS 约束保障")
    q.add_argument("--include-uid", type=int, action="append", help="纳入接管的非系统用户 UID，可重复")
    q.add_argument("--dns-server", help="明确指定上游 DNS IP")
    q.add_argument("--health-domain", action="append", help="用于实际 DNS/TLS 健康检查的域名，可重复")
    q.add_argument("--management-cidr", action="append", help="保护的管理地址范围，可重复")
    q.add_argument("--policy", help="完整网络策略 JSON，不能与逐项策略参数混用")
    q.add_argument("--binary", help="可信后端二进制；未指定时获取已测试稳定版")
    q.add_argument("--entry", help="首次安装使用的单文件 v6only 入口")
    q.add_argument("--confirm-timeout", type=int, default=180, help="确认期限，30–3600 秒")


def manager():
    return RUNTIME.Manager(HOST.Host(), TRANSACTIONS, HOST, OBSERVABILITY, {"singbox": SINGBOX, "dnsmasq": DNSMASQ}, normalizer=normalize)


def requested_policy(args):
    if args.policy:
        if any(getattr(args, name, None) for name in ("include_uid", "dns_server", "health_domain", "management_cidr")):
            raise Failure("--policy 不能与逐项策略参数混用。", 2)
        try:
            result = json.loads(read_text(args.policy))
            result["health_domains"] = sorted(set(normalize(x) for x in result["health_domains"]))
            return HOST.validate_policy(result)
        except (ValueError, KeyError, TypeError):
            raise Failure("网络策略文件无效。", 2)
    if not any(getattr(args, name, None) for name in ("include_uid", "dns_server", "health_domain", "management_cidr")):
        return None
    result = HOST.policy_defaults()
    result["include_uids"] = sorted(set(args.include_uid or []))
    result["dns_upstream"] = args.dns_server
    result["health_domains"] = sorted(set(normalize(x) for x in (args.health_domain or [])))
    try:
        result["management_cidrs"] = sorted(set(str(ipaddress.ip_network(x, strict=False)) for x in (args.management_cidr or [])))
        peer = os.environ.get("SSH_CONNECTION", "").split()
        if peer:
            address = ipaddress.ip_address(peer[0])
            result["management_cidrs"] = sorted(set(result["management_cidrs"] + [str(ipaddress.ip_network(str(address) + ("/32" if address.version == 4 else "/128")))]))
    except ValueError:
        raise Failure("管理地址范围不是合法 CIDR。", 2)
    return result


def help_text(p):
    p.print_help()
    print("\n示例：v6only add '*.openai.com'\n      v6only apply --dry-run")
    print("add/remove/import 仅编辑待应用清单；import 合并去重；export 拒绝覆盖现有文件。")
    print("生命周期功能处于实验阶段；未经显式授权不修改网络。所有写命令支持零写入 --dry-run。")
    print("开发版使用 V6ONLY_STATE_DIR 或 XDG_STATE_HOME/v6only（默认 ~/.local/state/v6only）。")
    print("候选：v6only config render --dns-server 192.0.2.53 --dry-run（示例地址需替换）。")
    print("config validate 只检查候选；不会启动服务、TUN 或安装后端。")
    print("退出码：0 成功/已预览/等待确认；1 运行错误；2 参数错误；3 前置条件不满足；4 校验失败；5 恢复或冲突失败。")


def run(args, p):
    command = args.command
    dry = getattr(args, "dry_run", False)
    if command == "help":
        subcommand = getattr(args, "subcommand", None)
        if subcommand:
            try:
                p.parse_args([subcommand, "-h"])
            except SystemExit:
                pass
        else:
            help_text(p)
        return 0
    if command == "version":
        print(VERSION)
        return 0
    if command == "_netcheck":
        domain = normalize(args.domain)
        if domain.startswith("*."):
            raise Failure("健康检查目标不能为通配规则。", 2)
        if dry:
            print("计划查询 DNS 并建立 IPv6 TLS 连接；本次不联网。")
            return 0
        if args.uid is not None:
            if os.geteuid() != 0 or args.uid < 1000:
                raise Failure("内部用户检查需要 root 和非系统 UID。", 3)
            import pwd
            try:
                account = pwd.getpwuid(args.uid)
            except KeyError:
                raise Failure("检查目标 UID 对应的用户不存在。", 3)
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(args.uid)
        report = OBSERVABILITY.network_test(domain)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ipv6_available"] else 4
    if command in {"_recover", "_guard"}:
        if dry:
            print("计划检查项目事务或恢复故障保护规则；本次不修改系统。")
            return 0
        if os.geteuid() != 0:
            raise Failure("内部服务入口需要 root。", 3)
        operation = manager()
        result = operation.recover(args.transaction, automatic=True) if command == "_recover" else operation.guard()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if command == "backend" and args.operation == "probe":
        if dry:
            print("计划只读检查指定 sing-box 版本；本次不执行外部进程、不写文件。")
        else:
            adapter = SINGBOX if args.backend == "singbox" else DNSMASQ
            print(json.dumps(adapter.probe(args.binary), ensure_ascii=False, indent=2))
        return 0
    if command == "config" and args.operation == "validate":
        try:
            candidate = json.loads(read_text(args.file))
        except (ValueError, RecursionError):
            raise Failure("候选文件不是有效 JSON。")
        adapter = DNSMASQ if isinstance(candidate, dict) and candidate.get("backend") == "dnsmasq" else SINGBOX
        adapter.verify_candidate(candidate, normalize)
        if dry:
            checker = "dnsmasq --test" if adapter is DNSMASQ else "sing-box check"
            print("候选结构检查通过；计划检查后端版本并执行 " + checker + "；本次不写临时文件或运行外部校验器。")
        else:
            print(json.dumps(adapter.validate(candidate, args.binary, normalize), ensure_ascii=False, indent=2))
        return 0
    if command in {"confirm", "rollback", "purge"}:
        operation = manager()
        if dry:
            print(json.dumps(operation.plan(command, keep_logs=getattr(args, "keep_logs", False), remove_entry=getattr(args, "remove_entry", False)), ensure_ascii=False, indent=2))
            return 0
        if os.geteuid() != 0:
            raise Failure("生命周期操作需要 root。", 3)
        state = operation.read()
        if command == "purge":
            result = operation.purge(args.yes, args.keep_logs, args.remove_entry)
        else:
            identifier = args.transaction or state["active_transaction"] or (state["current_transaction"] if command == "rollback" else None)
            if not identifier:
                raise Failure("没有可确认或恢复的当前事务。", 3)
            if command == "rollback" and not args.accept_network_change:
                raise Failure("实际恢复需要 --accept-network-change。", 3)
            result = operation.confirm(identifier) if command == "confirm" else operation.recover(identifier)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    deployed = os.environ.get("V6ONLY_ENTRY") == "/usr/local/sbin/v6only"
    default = Path("/var/lib/v6only") if deployed else Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "v6only"
    store = Store(getattr(args, "state_dir", os.environ.get("V6ONLY_STATE_DIR", str(default))))
    if command in LIFECYCLE or command == "backend" or (command == "apply" and not dry):
        operation = manager()
        if dry:
            result = operation.plan(command, getattr(args, "backend", None), requested_policy(args), domains=store.read()["domains"])
        else:
            pending = store.read()
            result = operation.execute(command, pending["domains"], backend=getattr(args, "backend", None),
                                       policy=requested_policy(args), binary=args.binary, entry=args.entry,
                                       accept=args.accept_network_change, broad=args.accept_broad_ipv4_block,
                                       downgrade=args.accept_dns_downgrade, ttl=args.confirm_timeout, pending_state=pending)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if command in {"add", "remove", "import"}:
        incoming = parse_domains(read_text(args.file)) if command == "import" else sorted(set(normalize(x) for x in args.domains))
        def edit(data):
            before = set(data["domains"])
            after = before - set(incoming) if command == "remove" else before | set(incoming)
            added, removed = sorted(after - before), sorted(before - after)
            if dry:
                print(json.dumps({"计划新增": added, "计划删除": removed, "写入": False}, ensure_ascii=False, indent=2))
            elif added or removed:
                data["revision"] += 1
                data["domains"] = sorted(after)
                data["events"].append({"time": now(), "uid": os.geteuid(), "action": command,
                                       "revision": data["revision"], "transaction": None,
                                       "added": added, "removed": removed, "result": "成功"})
                data["events"] = data["events"][-MAX_EVENTS:]
                store.write(data)
                print(f"待应用清单已更新：新增 {len(added)}，删除 {len(removed)}；尚未应用网络配置。")
            else:
                print("清单无需更改。")
        if dry:
            edit(store.read())
        else:
            with store.locked():
                edit(store.read())
        return 0
    data = store.read()
    if command == "config":
        adapter = SINGBOX if args.backend == "singbox" else DNSMASQ
        candidate = adapter.render(data["domains"], data["revision"], args.dns_server)
        payload = json.dumps(candidate, ensure_ascii=False, indent=2) + "\n"
        if len(payload.encode()) > MAX_INPUT:
            raise Failure("候选配置超过 4 MiB 上限；请缩小清单后重试。")
        if args.output:
            destination = safe_path(args.output)
            if destination.exists() or not destination.parent.is_dir():
                raise Failure("候选目标必须是已有目录中的新文件，拒绝覆盖用户内容。", 3)
            if destination in (store.path, store.root / "write.lock"):
                raise Failure("候选文件不得占用内部状态路径。", 3)
            if not dry:
                atomic_write(destination, payload)
                print("已生成后端候选；尚未通过官方校验，未应用网络配置。")
                return 0
        print(payload, end="")
    elif command == "list":
        print("\n".join(data["domains"]))
    elif command == "export":
        destination = safe_path(args.file)
        if destination.exists():
            raise Failure("导出目标已存在；请选择新文件，避免覆盖用户内容。", 3)
        if not destination.parent.is_dir():
            raise Failure("导出目标父目录不存在。", 3)
        if destination == store.path or destination == store.root / "write.lock":
            raise Failure("导出目标不得占用内部状态文件。", 3)
        if dry:
            print(f"计划导出 {len(data['domains'])} 条规则到新文件；不写入文件或审计。")
        else:
            atomic_write(destination, "".join(x + "\n" for x in data["domains"]))
            print(f"已导出 {len(data['domains'])} 条规则。")
    elif command == "apply":
        result = preview(data)
        result["执行计划"] = manager().plan("apply", policy=requested_policy(args), domains=data["domains"])
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif command == "status":
        data = store.read()
        if data["domains"]:
            print(f"待应用规则：{len(data['domains'])}；修订：{data['revision']}。")
        print(json.dumps(manager().status(), ensure_ascii=False))
    elif command == "check":
        if dry:
            print("本地清单结构校验通过；计划检查归属资源及已启用服务的 DNS/TLS，不执行外部命令或写日志。")
            return 0
        result = manager().check()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 4
    elif command == "doctor":
        print(json.dumps(HOST.Host().inspect(), ensure_ascii=False, indent=2))
    elif command == "test":
        domain = normalize(args.domain)
        if domain.startswith("*."):
            raise Failure("测试目标不能为通配规则。", 2)
        if dry:
            print("计划 DNS 和 IPv6 TCP/TLS 检查；本次不联网、不写健康记录。")
            return 0
        entry = os.environ.get("V6ONLY_ENTRY")
        if not entry:
            raise Failure("网络测试请通过 Bash 管理入口执行。", 3)
        try:
            result = subprocess.run([entry, "_netcheck", domain], capture_output=True, text=True, timeout=25)
        except subprocess.TimeoutExpired:
            raise Failure("网络诊断超过总期限。", 4)
        if result.stdout:
            print(result.stdout, end="")
            try:
                health = json.loads(result.stdout)
                with store.locked():
                    records = manager().records if deployed else OBSERVABILITY.Records(store.root / "logs")
                    records.append("health", "test", "成功" if result.returncode == 0 else "失败", details=health)
            except ValueError:
                raise Failure("网络检查子进程返回了无效报告。", 4)
        if result.returncode:
            return 4
    elif command in {"history", "logs"}:
        operation = manager()
        if command == "logs" and args.kind == "service":
            if not 1 <= args.limit <= 10000:
                raise Failure("日志条数必须为 1–10000。", 2)
            result = HOST.Host().command(["journalctl", "--namespace=v6only", "--no-pager", "-n", str(args.limit)])
            print(result.stdout, end="")
            return 0
        for event in data["events"]:
            selected = event if command == "history" else {k: v for k, v in event.items() if k not in {"added", "removed"}}
            print(json.dumps(selected, ensure_ascii=False))
        for event in operation.records.read("changes" if command == "history" else args.kind):
            print(json.dumps(event, ensure_ascii=False))
        if command == "logs" and args.kind == "health" and not deployed:
            for event in OBSERVABILITY.Records(store.root / "logs").read("health", args.limit):
                print(json.dumps(event, ensure_ascii=False))
    return 0


def interactive(p):
    print("v6only 中文菜单\n1. 查看待应用清单\n2. 添加域名\n3. 删除域名\n4. 导入清单\n5. 导出清单\n6. 配置预览\n7. 本地与运行状态\n8. 帮助\n9. 安装\n10. 应用\n11. 确认当前事务\n12. 切换后端\n13. 域名网络测试\n14. 健康检查\n15. 环境诊断\n16. 日志\n17. 历史\n18. 升级\n19. 重装\n20. 停用\n21. 启用\n22. 回滚\n23. 卸载\n24. 清理\n25. 版本\n0. 退出")
    choice = input("请选择：").strip()
    commands = {"1": ["list"], "2": ["add"], "3": ["remove"], "4": ["import"], "5": ["export"],
                "6": ["apply", "--dry-run"], "7": ["status"], "8": ["help"], "9": ["install"], "10": ["apply"],
                "11": ["confirm"], "12": ["backend", "use"], "13": ["test"], "14": ["check"], "15": ["doctor"],
                "16": ["logs"], "17": ["history"], "18": ["update"], "19": ["reinstall"], "20": ["disable"],
                "21": ["enable"], "22": ["rollback"], "23": ["uninstall"], "24": ["purge"], "25": ["version"]}
    if choice == "0":
        return 0
    if choice not in commands:
        raise Failure("无效的菜单选项。", 2)
    argv = commands[choice]
    if choice in {"2", "3", "4", "5", "13"}:
        argv.append(input("请输入域名或文件路径（无需 shell 引号）：").strip())
    if choice in {"9", "12"}:
        selected = input("后端（singbox/dnsmasq，默认 singbox）：").strip() or "singbox"
        argv += (["--backend", selected] if choice == "9" else [selected])
    if choice == "9":
        argv += ["--policy", input("网络策略文件路径（参考 examples/policy.json.example）：").strip()]
        current = Path(os.environ.get("V6ONLY_ENTRY", ""))
        built = current.parent.parent / "dist/v6only"
        argv += ["--entry", str(built if current.name == "v6only.sh" and built.is_file() else current)]
    if choice == "24":
        if input("保留日志？输入 y 保留，默认清理：").strip().lower() == "y":
            argv.append("--keep-logs")
    if choice in {"9", "10", "12", "18", "19", "20", "21", "22", "23", "24"}:
        run(p.parse_args([*argv, "--dry-run"]), p)
        if choice == "24":
            if input("输入 清理项目数据 确认不可恢复的清理，其他输入取消：").strip() != "清理项目数据":
                return 0
            argv.append("--yes")
        else:
            backend = selected if choice in {"9", "12"} else manager().read()["backend"]
            if choice in {"20", "22", "23"}:
                phrase = "确认网络变更"
            elif backend == "dnsmasq":
                print("DNS 约束模式不能提供 TUN IPv6-only 出站的同等保障。")
                phrase = "确认DNS降级"
                argv.append("--accept-dns-downgrade")
            else:
                print("故障保护可能阻断选定用户更广泛的非管理 IPv4 流量。")
                phrase = "确认IPv4故障保护"
                argv.append("--accept-broad-ipv4-block")
            if input("输入 " + phrase + " 执行上述网络变更，其他输入取消：").strip() != phrase:
                return 0
            argv.append("--accept-network-change")
    return run(p.parse_args(argv), p)


def main():
    p = parser()
    try:
        if sys.version_info < (3, 9) or sys.platform != "linux":
            raise Failure("当前开发版需要 Linux 与 Python 3.9 或更新版本。", 3)
        if len(sys.argv) == 1:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                help_text(p)
                return 0
            return interactive(p)
        args = p.parse_args()
        if args.command is None:
            help_text(p)
            return 0
        return run(args, p)
    except (Failure, SINGBOX.BackendFailure, DNSMASQ.BackendFailure, TRANSACTIONS.TransactionError,
            HOST.HostError, RUNTIME.RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except (OSError, EOFError) as exc:
        # 不回显路径或原始输入，避免泄露带凭据输入。
        print(f"操作失败：{type(exc).__name__}；请检查文件权限、路径或输入。", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("操作已取消。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

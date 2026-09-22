"""统一生命周期管理。真实网络操作需要显式运行授权；测试使用独立适配器。"""
import contextlib
import copy
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import tarfile
import urllib.request
import uuid


class RuntimeError(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


def initial_state():
    return {"schema": 1, "installed": False, "enabled": False, "backend": None, "backend_version": None,
            "active_transaction": None, "current_transaction": None, "resources": {}, "services": [],
            "policy": None, "domains": [], "nft_table": None, "nft_snapshot": None, "entry_sha256": None,
            "dependency_records": [], "dependency_pending": None, "kernel_snapshot": None, "mutable_resources": {}, "journal_owned": False}


class Manager:
    def __init__(self, host, transactions, host_module, observations, backends, normalizer=None):
        self.host, self.tx, self.hm, self.backends = host, transactions, host_module, backends
        self.root = host.root
        self.normalizer = normalizer
        if host.mode == "live" and normalizer is None:
            raise RuntimeError("真实运行适配器缺少域名校验器。")
        self.directory = self.root / "var/lib/v6only"
        self.path = self.directory / "runtime.json"
        self.journal = transactions.Journal(self.root, self.directory / "transactions")
        self.records = observations.Records(self.root / "var/log/v6only")

    def read(self):
        if not self.path.exists():
            return initial_state()
        if self.path.is_symlink() or self.path.stat().st_mode & 0o077:
            raise RuntimeError("运行状态权限或路径异常。")
        try:
            state = json.loads(self.path.read_text())
            if set(state) != set(initial_state()) or state["schema"] != 1 or type(state["resources"]) is not dict:
                raise ValueError
            if type(state["installed"]) is not bool or type(state["enabled"]) is not bool or not isinstance(state["domains"], list):
                raise ValueError
            if self.normalizer and state["domains"] != sorted(set(self.normalizer(x) for x in state["domains"])):
                raise ValueError
            if state["backend"] not in {None, "singbox", "dnsmasq"} or not isinstance(state["services"], list):
                raise ValueError
            if any(not self.tx.allowed(path) or path == "/usr/sbin/policy-rc.d" for path in state["resources"]):
                raise ValueError
            return state
        except (ValueError, KeyError, TypeError):
            raise RuntimeError("运行状态损坏，未覆盖原文件。", 4)

    def write(self, state):
        self.tx.atomic_json(self.path, state)

    @contextlib.contextmanager
    def locked(self):
        for path in [self.directory, *self.directory.parents]:
            if path.is_symlink():
                raise RuntimeError("运行状态目录不能包含符号链接。")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.stat().st_mode & 0o077:
            raise RuntimeError("运行数据目录必须为私有目录。")
        fd = os.open(self.directory / "runtime.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def plan(self, action, backend=None, policy=None, keep_logs=False, remove_entry=False, domains=None):
        state = self.read()
        steps = ["校验平台和资源冲突", "校验候选与官方版本", "保存项目归属快照", "安排独立回滚",
                 "临时应用并检查健康", "用户确认提交或到期恢复"]
        if action == "uninstall":
            steps = ["检查外部修改冲突", "安排独立恢复任务", "退出接管并恢复项目网络资源", "验证恢复结果", "移除专属服务和后端", "保留清单、记录、备份、入口并等待确认"]
        elif action == "disable":
            steps = ["明确解除接管和严格限制", "安排独立恢复任务", "停止项目服务并移除项目网络规则", "验证恢复并等待确认"]
        elif action == "confirm":
            steps = ["核对唯一当前事务及截止时间", "重新检查资源摘要和健康", "提交状态", "仅取消该事务的恢复任务"]
        elif action == "rollback":
            steps = ["核对当前事务和归属快照", "检查外部修改冲突", "恢复项目资源与先前服务", "验证恢复", "保留历史记录"]
        elif action == "purge":
            steps = ["核实已确认的卸载记录", "检查残留网络资源和未知文件", "清理项目配置、状态与备份",
                     "保留所有项目日志" if keep_logs else "清理项目日志及专属 journal 命名空间",
                     "删除未被改动的管理入口" if remove_entry else "保留管理入口", "保留共享依赖"]
        result = {"action": action, "mode": self.host.mode, "installed": state["installed"], "dry_run": True,
                "backend": backend or state["backend"] or "singbox", "policy": policy or state["policy"],
                "steps": steps, "active_transaction": state["active_transaction"],
                "writes": False, "network_access": "本次不联网；实际安装缺失工具/获取后端时会访问官方发布或已配置的 APT 仓库。",
                "requirements": ["root + systemd", "明确非系统 UID、上游 DNS、健康域名", "--accept-network-change",
                                 "singbox：--accept-broad-ipv4-block；dnsmasq：--accept-dns-downgrade"],
                "scope": "仅选定 UID；系统 DNS 文件保持不变；普通 TCP/UDP 53 查询由项目 NAT 分派；独立 DoH 不在保证范围。"}
        if result["policy"] and action in {"install", "apply", "backend", "update", "reinstall", "enable"}:
            self.hm.validate_policy(result["policy"])
            selected = domains if domains is not None and action in {"install", "apply"} else state["domains"]
            backend = result["backend"]
            result["candidate"] = (self.backends[backend].runtime_config(selected, result["policy"]) if backend == "singbox" else
                                   self.backends[backend].configs(selected, result["policy"]["dns_upstream"], result["policy"]["dns_port"]))
            result["nft_candidate"] = self.hm.nft_config(result["policy"], state["nft_table"] or "v6only_000000000000", backend == "singbox")
            result["validation"] = "仅预览；尚未执行环境检查或外部校验。全零表名是示例，实际首次安装使用唯一归属标识。"
        return result

    def audit(self, action, result, identifier=None, details=None):
        self.records.append("audit", action, result, identifier, details)

    def owned_conflicts(self, state):
        conflicts = [path for path, signature in state["resources"].items() if self.journal.inspect(path) != signature]
        if state.get("nft_table") and self.host.nft_snapshot(state["nft_table"]) != state.get("nft_snapshot"):
            conflicts.append("nft:" + state["nft_table"])
        if state.get("policy") and self.host.kernel_conflicts(state["policy"], state.get("kernel_snapshot")):
            conflicts.append("kernel:规则/路由/地址")
        return conflicts

    def bootstrap(self, entry, state):
        target = self.root / "usr/local/sbin/v6only"
        if state["entry_sha256"]:
            if target.is_symlink() or not target.is_file() or target.stat().st_mode & 0o022 or self.tx.digest(target) != state["entry_sha256"]:
                raise RuntimeError("管理入口被外部修改，拒绝覆盖。", 5)
            return
        if target.exists() or target.is_symlink():
            if (not target.is_symlink() and entry and Path(entry).is_file() and
                    self.tx.digest(target) == self.tx.digest(entry) and b"V6ONLY_PY_" in target.read_bytes()):
                state["entry_sha256"] = self.tx.digest(target)
                self.write(state)
                return
            raise RuntimeError("系统中已有不同的同名管理入口，无法证明归属。")
        if not entry or not Path(entry).is_file():
            raise RuntimeError("首次安装需要 --entry 指向构建后的单文件 v6only。")
        content = Path(entry).read_bytes()
        if not content.startswith(b"#!/usr/bin/env bash") or b"V6ONLY_PY_" not in content:
            raise RuntimeError("安装入口必须是本项目生成的单文件发行产物。")
        self.tx.atomic_bytes(target, content, 0o755)
        state["entry_sha256"] = hashlib.sha256(content).hexdigest()
        self.write(state)

    def obtain_binary(self, backend, binary):
        adapter = self.backends[backend]
        if self.host.mode == "simulation":
            content = Path(binary).read_bytes() if binary else b"SIMULATED-BINARY-NOT-EXECUTABLE\n"
            return content, {"mode": "simulation", "version": "1.14.1" if backend == "singbox" else "2.91"}
        if binary:
            adapter.probe(binary)
            content = Path(binary).read_bytes()
            return content, {"source": "显式指定的可信本地文件", "sha256": hashlib.sha256(content).hexdigest()}
        if backend == "dnsmasq":
            executable = shutil.which("dnsmasq")
            if not executable:
                raise RuntimeError("未找到 dnsmasq 2.91；安装器可安装 dnsmasq-base 后再重试，或显式提供 --binary。")
            adapter.probe(executable)
            content = Path(executable).read_bytes()
            return content, {"source": "已安装的 dnsmasq-base", "sha256": hashlib.sha256(content).hexdigest()}
        if platform.machine() not in {"x86_64", "amd64"}:
            raise RuntimeError("自动获取后端当前仅支持 Linux amd64；其他架构需另行版本验证。")
        url = "https://github.com/SagerNet/sing-box/releases/download/v1.14.1/sing-box-1.14.1-linux-amd64.tar.gz"
        expected = "12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f"
        with urllib.request.urlopen(url, timeout=45) as response:
            archive = response.read(100 * 1024 * 1024 + 1)
        if len(archive) > 100 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != expected:
            raise RuntimeError("后端官方归档摘要不符，未执行。", 4)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            member = bundle.getmember("sing-box-1.14.1-linux-amd64/sing-box")
            if not member.isfile() or member.size > 160 * 1024 * 1024:
                raise RuntimeError("后端归档结构非法。", 4)
            content = bundle.extractfile(member).read()
        return content, {"source": url, "archive_sha256": expected, "sha256": hashlib.sha256(content).hexdigest(), "signature_verified": False}

    def package_state(self, packages):
        results = {}
        for package in packages:
            result = self.host.command(["dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", package], check=False)
            results[package] = result.stdout.strip() if result.returncode == 0 else "未安装"
        return results

    def install_dependencies(self, packages, state):
        """APT 自动安装在独立可恢复的禁止自启窗口内执行，原 policy-rc.d 原样恢复。"""
        if not packages:
            return state
        if set(packages) - {"iproute2", "nftables", "ca-certificates", "dnsmasq-base"}:
            raise RuntimeError("依赖计划包含不允许自动安装的软件包。")
        if not shutil.which("apt-get") or not shutil.which("dpkg-query"):
            raise RuntimeError("缺少支持的 APT/dpkg 工具。")
        if "dnsmasq-base" in packages:
            candidate = self.host.command(["apt-cache", "policy", "dnsmasq-base"]).stdout
            import re
            if not re.search(r"Candidate:\s*2\.91(?:-|\s)", candidate):
                raise RuntimeError("当前发行版仓库没有已测试的 dnsmasq 2.91；拒绝自动安装不同版本。")
        before_packages = self.package_state(packages)
        policy = "#!/bin/sh\n# v6only 临时禁止依赖安装时自动启动系统服务\nexit 101\n"
        data = self.journal.create("dependencies", [{"path": "/usr/sbin/policy-rc.d", "content": policy, "mode": 0o755, "transient": True}], state, state, ttl=600)
        data["packages_before"] = before_packages
        self.journal.save(data)
        state["dependency_pending"] = data["id"]
        self.write(state)
        self.audit("dependencies", "已准备", data["id"], {"packages": packages})
        try:
            self.host.arm(data["id"], data["deadline"])
            self.journal.save(data, "rollback_armed")
            self.journal.apply_files(data)
            # needrestart 仅列出需要重启的服务；禁止在安装窗口自动重启其他项目。
            command = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "apt-get", "-o", "Dpkg::Use-Pty=0", "--yes", "--no-install-recommends", "install", *packages]
            self.host.command(command, timeout=240)
        finally:
            self._recover_dependencies(data)
        return self.read()

    def _recover_dependencies(self, data):
        if data["status"] == "restored":
            return
        if self.host.mode == "live":
            # 父进程退出不代表 apt/dpkg 子进程已退出；在安装锁释放前保留禁止自启策略。
            for path in ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"):
                try:
                    with open(path, "r+") as stream:
                        fcntl.lockf(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.lockf(stream, fcntl.LOCK_UN)
                except BlockingIOError:
                    raise RuntimeError("APT/dpkg 仍在运行；保留禁止自启策略，独立恢复任务将重试。", 5)
        self.journal.restore_files(data)
        state = self.read()
        if state["dependency_pending"] not in {None, data["id"]}:
            raise RuntimeError("依赖恢复事务与当前状态冲突。", 5)
        packages = self.package_state(list(data["packages_before"]))
        state["dependency_records"].append({"transaction": data["id"], "before": data["packages_before"], "after": packages, "retained": True})
        state["dependency_pending"] = None
        self.write(state)
        self.journal.save(data, "restored")
        self.host.disarm(data["id"])
        self.audit("dependencies", "自启策略已恢复", data["id"], {"packages": packages, "说明": "新装共享依赖保留，不自动删除。"})

    def unit(self, name, command, backend=True):
        dependencies = "Requires=v6only-guard.service\nAfter=network-online.target v6only-guard.service\n" if backend else "After=network-online.target\n"
        return (f"[Unit]\nDescription=v6only {name}\nWants=network-online.target\n" + dependencies +
                f"[Service]\nType={'simple' if backend else 'oneshot'}\nExecStart={command}\n" +
                ("Restart=on-failure\nRestartSec=2s\n" if backend else "RemainAfterExit=yes\n") +
                "User=root\nUMask=0077\nLogNamespace=v6only\nStandardOutput=journal\nStandardError=journal\n"
                "[Install]\nWantedBy=multi-user.target\n")

    def files(self, backend, domains, policy, content):
        binary_path = "/opt/v6only/bin/" + ("sing-box" if backend == "singbox" else "dnsmasq")
        files = [{"path": binary_path, "content": content, "mode": 0o755}]
        services = ["v6only-guard.service"]
        if backend == "singbox":
            config = self.backends[backend].runtime_config(domains, policy)
            files += [{"path": "/etc/v6only/singbox.json", "content": json.dumps(config, ensure_ascii=False, indent=2) + "\n"},
                      {"path": "/etc/systemd/system/v6only-singbox.service", "content": self.unit("sing-box", binary_path + " run -c /etc/v6only/singbox.json"), "mode": 0o644}]
            services.append("v6only-singbox.service")
        else:
            configs = self.backends[backend].configs(domains, policy["dns_upstream"], policy["dns_port"])
            for name, configuration in configs.items():
                unit = "v6only-dns-" + name + ".service"
                command = binary_path + " --keep-in-foreground --conf-file=/etc/v6only/dns-" + name + ".conf"
                files += [{"path": "/etc/v6only/dns-" + name + ".conf", "content": configuration},
                          {"path": "/etc/systemd/system/" + unit, "content": self.unit("DNS " + name, command), "mode": 0o644}]
                services.append(unit)
        files += [{"path": "/etc/systemd/system/v6only-guard.service", "content": self.unit("故障保护", "/usr/local/sbin/v6only _guard", backend=False), "mode": 0o644},
                  {"path": "/etc/systemd/journald@v6only.conf", "content": "[Journal]\nStorage=persistent\nSystemMaxUse=100M\nMaxRetentionSec=30day\n"},
                  {"path": "/etc/systemd/system/systemd-journald@v6only.service.d/v6only.conf", "content": "[Service]\nLogsDirectoryMode=0700\nUMask=0077\n"}]
        return files, services

    def execute(self, action, domains, backend=None, policy=None, binary=None, entry=None,
                accept=False, broad=False, downgrade=False, ttl=180, fault=None, pending_state=None):
        if self.host.mode == "live" and not accept:
            raise RuntimeError("实际生命周期操作需要显式 --accept-network-change；可先使用 --dry-run。")
        if self.normalizer:
            domains = sorted(set(self.normalizer(x) for x in domains))
        with self.locked():
            before = self.read()
            if before["active_transaction"] or before["dependency_pending"]:
                raise RuntimeError("已有待处理事务，请先确认或恢复该事务。")
            if action != "install" and not before["installed"]:
                raise RuntimeError("尚未安装运行组件。")
            backend = backend or before["backend"] or "singbox"
            policy = copy.deepcopy(policy or before["policy"])
            if not policy:
                raise RuntimeError("需要明确网络策略；先使用 install --dry-run 查看要求。")
            self.hm.validate_policy(policy)
            turning_on = action not in {"disable", "uninstall"}
            if before["policy"] and any(before["policy"][key] != policy[key] for key in ("route_table", "rule_priority", "tun_addresses", "fake_ipv4", "fake_ipv6")):
                raise RuntimeError("路由标识和虚拟地址范围不能在同一实例内更改；请先完成卸载与清理，再安装新策略。")
            if turning_on and backend == "singbox" and not broad:
                raise RuntimeError("需确认故障时可能阻断选定 UID 的更多非管理 IPv4 流量：--accept-broad-ipv4-block。")
            if turning_on and backend == "dnsmasq" and not downgrade:
                raise RuntimeError("即将切换为 DNS 约束模式，无法提供与 TUN IPv6-only 出站相同的保障；需 --accept-dns-downgrade。")
            report = self.host.inspect()
            bootstrap_report = dict(report, missing_tools=[x for x in report["missing_tools"] if x not in {"ip", "nft"}])
            self.host.require_supported(bootstrap_report, require_tun=turning_on and backend == "singbox")
            self.bootstrap(entry, before)
            pending_path = self.directory / "state.json"
            if action == "install" and not pending_path.exists():
                if pending_state is None:
                    pending_state = {"schema": 1, "revision": 1 if domains else 0, "domains": domains, "events": []}
                    if domains:
                        pending_state["events"].append({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "uid": os.geteuid(),
                                                        "action": "import", "revision": 1, "transaction": None, "added": domains, "removed": [], "result": "成功"})
                self.tx.atomic_json(pending_path, pending_state)
            packages = []
            if self.host.mode == "live":
                packages += [name for command, name in (("ip", "iproute2"), ("nft", "nftables")) if command in report["missing_tools"]]
                if not Path("/etc/ssl/certs/ca-certificates.crt").exists():
                    packages.append("ca-certificates")
                if turning_on and backend == "dnsmasq" and not binary and not shutil.which("dnsmasq"):
                    packages.append("dnsmasq-base")
                before = self.install_dependencies(packages, before)
            report = self.host.inspect(policy, before["installed"] and before["backend"] == "singbox", check_routes=backend == "singbox",
                                       require_peer_exclusion=turning_on and backend == "singbox")
            self.host.require_supported(report, require_tun=turning_on and backend == "singbox")
            conflicts = self.owned_conflicts(before)
            if conflicts:
                raise RuntimeError("项目资源被外部修改，停止操作：" + ", ".join(conflicts), 5)
            if turning_on:
                self.host.check_ports(policy, backend, before)
                if not before["journal_owned"]:
                    retained = self.retained_logs()
                    if self.host.namespace_path().exists() and not retained:
                        raise RuntimeError("同名 journal 命名空间已存在且无法证明归属。")
                    before["journal_owned"] = True
                    self.write(before)
                if backend == "singbox":
                    cache_name = "/var/lib/v6only/singbox-cache.db"
                    cache_path = self.root / cache_name.lstrip("/")
                    if cache_path.is_symlink():
                        raise RuntimeError("运行缓存不能是符号链接。", 5)
                    if cache_name not in before["mutable_resources"]:
                        if cache_path.exists():
                            raise RuntimeError("已有同名缓存不在项目归属清单内。")
                        before["mutable_resources"][cache_name] = {"purpose": "持久化 FakeIP 映射", "mutable": True, "existed_before": False}
                        self.write(before)
            if action == "install" and before["installed"]:
                if before["backend"] == backend and before["policy"] == policy:
                    return {"changed": False, "说明": "已安装相同后端与策略。", "mode": self.host.mode}
                raise RuntimeError("已安装；后端变更请使用 backend use，清单变更请使用 apply。")
            if action == "disable" and not before["enabled"]:
                return {"changed": False, "mode": self.host.mode, "说明": "已停用。"}
            if action == "update" and not binary and not entry and before["backend_version"] == ("1.14.1" if backend == "singbox" else "2.91"):
                return {"changed": False, "mode": self.host.mode, "说明": "当前已经是本版本管理器锁定的已测试稳定版；未查询或切换到未经验证的新版本。"}
            if action not in {"install", "apply"}:
                domains = before["domains"]
            after = copy.deepcopy(before)
            after.update(installed=action != "uninstall", enabled=turning_on, backend=backend,
                         backend_version="1.14.1" if backend == "singbox" else "2.91", policy=policy, domains=domains)
            after["nft_table"] = before["nft_table"] or "v6only_" + uuid.uuid4().hex[:12]
            if before["nft_table"] is None and self.host.nft_snapshot(after["nft_table"]) is not None:
                raise RuntimeError("生成的项目防火墙名称已被占用，拒绝覆盖。")
            self.bootstrap(entry, before)
            after["entry_sha256"] = before["entry_sha256"]
            if turning_on:
                if action in {"install", "update", "reinstall", "backend"}:
                    content, provenance = self.obtain_binary(backend, binary)
                else:
                    source = self.root / "opt/v6only/bin" / ("sing-box" if backend == "singbox" else "dnsmasq")
                    content, provenance = source.read_bytes(), {"source": "已安装的项目专属后端"}
                files, after["services"] = self.files(backend, domains, policy, content)
                nft = self.hm.nft_config(policy, after["nft_table"], backend == "singbox")
                files.append({"path": "/etc/v6only/rules.nft", "content": nft})
            else:
                provenance, nft = {}, None
                if action == "uninstall":
                    files = [{"path": path, "content": None} for path in before["resources"]]
                    after["services"] = []
                else:
                    files = []
            desired = {item["path"] for item in files}
            if turning_on:
                files += [{"path": path, "content": None} for path in before["resources"] if path not in desired]
            if action in {"update", "reinstall"} and entry:
                content = Path(entry).read_bytes()
                if not content.startswith(b"#!/usr/bin/env bash") or b"V6ONLY_PY_" not in content:
                    raise RuntimeError("新的管理入口不是本项目单文件产物。")
                files.append({"path": "/usr/local/sbin/v6only", "content": content, "mode": 0o755})
                after["entry_sha256"] = hashlib.sha256(content).hexdigest()
            for item in files:
                if item["path"] not in before["resources"] and item["path"] != "/usr/local/sbin/v6only" and self.journal.inspect(item["path"])["exists"]:
                    raise RuntimeError("同名资源已存在且不属于本项目：" + item["path"])
            transaction = self.journal.create(action, files, before, after, ttl)
            transaction["provenance"] = provenance
            transaction["before_report"] = report
            transaction["nft_after_content"] = nft
            transaction["nft_before_content"] = (self.root / "etc/v6only/rules.nft").read_text() if before["nft_snapshot"] is not None else None
            transaction["nft_phase"] = "before"
            self.journal.save(transaction)
            # 在保护接管前使用暂存二进制和生成配置运行官方校验，不启动服务。
            if turning_on and self.host.mode == "live":
                directory = self.journal.directory / transaction["id"]
                binary_index = next(i for i, item in enumerate(files) if item["path"].startswith("/opt/v6only/bin/"))
                temporary_binary = directory / ("after-" + str(binary_index))
                temporary_binary.chmod(0o700)
                if backend == "singbox":
                    self.backends[backend].validate_runtime(domains, policy, temporary_binary)
                else:
                    candidate = self.backends[backend].render(domains, 0, policy["dns_upstream"], policy["dns_port"])
                    self.backends[backend].validate(candidate, temporary_binary, lambda x: x)
            cursor = copy.deepcopy(before)
            cursor["active_transaction"] = transaction["id"]
            self.write(cursor)
            self.audit(action, "已准备", transaction["id"], {"mode": self.host.mode})
            try:
                self.host.arm(transaction["id"], transaction["deadline"])
                self.journal.save(transaction, "rollback_armed")
                if action == "uninstall":
                    self.stop_services(before)
                    if before["backend"] == "singbox":
                        self.host.cleanup_kernel(before["policy"], before["kernel_snapshot"])
                    transaction["nft_phase"] = "changing"
                    self.journal.save(transaction)
                    self.host.nft_replace(after["nft_table"], None)
                    after["nft_snapshot"] = None
                    after["kernel_snapshot"] = None
                    transaction["nft_phase"] = "after"
                    transaction["after"] = after
                    self.journal.save(transaction)
                    if not self.host.health(after, report)["ok"]:
                        raise RuntimeError("卸载前网络恢复验证失败，尚未移除组件。", 5)
                    self.host.stop_namespace()
                else:
                    # 在删换 unit 文件之前停止并禁用旧服务，避免遗留指向已删单元的启用链接。
                    # 现有独立故障保护表一直保留到候选替换完成。
                    self.stop_services(before)
                    if before["backend"] == "singbox" and before["enabled"]:
                        self.host.cleanup_kernel(before["policy"], before["kernel_snapshot"])
                self.journal.apply_files(transaction, fault=fault)
                self.host.reload()
                if turning_on:
                    transaction["nft_phase"] = "changing"
                    self.journal.save(transaction)
                    after["nft_snapshot"] = self.host.nft_replace(after["nft_table"], nft)
                    transaction["nft_phase"] = "after"
                    transaction["after"] = after
                    self.journal.save(transaction)
                if turning_on:
                    for service in after["services"]:
                        self.host.service(service, "enable")
                        self.host.service(service, "start")
                    self.host.wait_ready(after, transaction["deadline"])
                    after["kernel_snapshot"] = self.host.kernel_snapshot(policy) if backend == "singbox" else None
                else:
                    transaction["nft_phase"] = "changing"
                    self.journal.save(transaction)
                    self.host.nft_replace(after["nft_table"], None)
                    after["nft_snapshot"] = None
                    after["kernel_snapshot"] = None
                    transaction["nft_phase"] = "after"
                after["resources"] = {item["path"]: self.journal.inspect(item["path"]) for item in files if item.get("content") is not None and item["path"] != "/usr/local/sbin/v6only"}
                if action == "disable":
                    after["resources"] = before["resources"]
                after["current_transaction"] = transaction["id"]
                after["active_transaction"] = None
                transaction["after"] = after
                # 在有可能阻塞/失败的健康检查之前记录实际内核资源，确保恢复有归属依据。
                self.journal.save(transaction)
                health = self.host.health(after, report, deadline=transaction["deadline"])
                self.records.append("health", action, "成功" if health["ok"] else "失败", transaction["id"], health)
                if not health["ok"]:
                    raise RuntimeError("临时应用后健康检查失败。", 4)
                if datetime.datetime.now(datetime.timezone.utc) >= datetime.datetime.fromisoformat(transaction["deadline"]):
                    raise RuntimeError("临时应用超过确认期限，必须恢复。", 4)
                self.journal.save(transaction, "awaiting_confirm")
                self.audit(action, "等待确认", transaction["id"], {"deadline": transaction["deadline"]})
                return {"transaction": transaction["id"], "status": "awaiting_confirm", "deadline": transaction["deadline"],
                        "mode": self.host.mode, "impact": "已临时解除接管及严格限制" if action in {"disable", "uninstall"} else "已临时启用指定范围的网络策略",
                        "说明": "需执行 confirm --transaction 指定当前事务；超时由独立任务恢复。"}
            except Exception:
                try:
                    self._restore(transaction)
                except Exception as recovery:
                    self.journal.save(transaction, "restore_failed")
                    self.audit(action, "恢复失败", transaction["id"], {"category": type(recovery).__name__})
                    raise RuntimeError("操作失败且自动恢复失败；保留独立恢复任务和全部快照，需要人工处理。", 5) from recovery
                raise

    def stop_services(self, state):
        for service in reversed(state["services"]):
            if self.host.active(service):
                self.host.service(service, "stop")
            if (self.root / "etc/systemd/system" / service).exists() or self.host.mode == "simulation":
                self.host.service(service, "disable")

    def _restore(self, data):
        conflicts = self.journal.conflicts(data, accept_before=True)
        current = self.host.nft_snapshot(data["after"]["nft_table"])
        before_nft, after_nft = data["before"].get("nft_snapshot"), data["after"].get("nft_snapshot")
        if current != before_nft and current != after_nft:
            # 修改 syscall 与日志 fsync 之间崩溃时不能凭猜测删除规则。
            conflicts.append("nft:" + data["after"]["nft_table"])
        if conflicts:
            self.journal.save(data, "restore_failed")
            raise RuntimeError("恢复发现外部修改冲突：" + ", ".join(conflicts), 5)
        self.stop_services(data["after"])
        if data["after"]["backend"] == "singbox":
            self.host.cleanup_kernel(data["after"]["policy"], data["after"].get("kernel_snapshot"))
        self.journal.restore_files(data)
        self.host.reload()
        restored = copy.deepcopy(data["before"])
        restored["active_transaction"] = data["id"]
        self.write(restored)
        restored["nft_snapshot"] = self.host.nft_replace(data["after"]["nft_table"], data.get("nft_before_content"))
        if restored["enabled"]:
            for service in restored["services"]:
                self.host.service(service, "enable")
                self.host.service(service, "start")
            recovery_deadline = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60)).isoformat()
            self.host.wait_ready(restored, recovery_deadline)
            self.host.wait_settled(restored["policy"])  # B2-fix: wait_ready 后必须 wait_settled，确保路由稳定后再采集快照
            restored["kernel_snapshot"] = self.host.kernel_snapshot(restored["policy"]) if restored["backend"] == "singbox" else None
        health = self.host.health(restored, data.get("before_report"))
        if not health["ok"]:
            self.journal.save(data, "restore_failed")
            raise RuntimeError("恢复后的健康验证失败；保留恢复资料。", 5)
        restored["active_transaction"] = None
        self.write(restored)
        self.journal.save(data, "restored")
        self.host.disarm(data["id"])
        self.audit(data["action"], "已恢复", data["id"], {"mode": self.host.mode})

    def confirm(self, identifier):
        with self.locked():
            state = self.read()
            if state["active_transaction"] != identifier:
                raise RuntimeError("事务标识不是当前待确认事务，未取消任何任务。")
            data = self.journal.load(identifier)
            self.journal.confirmable(data)
            if self.host.nft_snapshot(data["after"]["nft_table"]) != data["after"]["nft_snapshot"]:
                raise RuntimeError("防火墙资源已改变，拒绝确认。", 5)
            health = self.host.health(data["after"], data.get("before_report"), deadline=data["deadline"])
            if not health["ok"]:
                self._restore(data)
                raise RuntimeError("确认时健康检查失败，已恢复。", 4)
            # 先持久化 committed，再取消当前定时器；迟到的恢复任务会读取提交状态并退出。
            self.journal.save(data, "committed")
            self.write(data["after"])
            self.host.disarm(identifier)
            self.records.append("changes", data["action"], "已提交", identifier, {"backend": data["after"]["backend"], "domains": data["after"]["domains"]})
            self.audit("confirm", "成功", identifier)
            self.prune_transactions()
            return {"transaction": identifier, "status": "committed", "mode": self.host.mode}

    def prune_transactions(self, keep=5):
        state = self.read()
        protected = {state["active_transaction"], state["current_transaction"]}
        if state["current_transaction"]:
            current = self.journal.load(state["current_transaction"])
            protected.add(current["before"].get("current_transaction"))
        closed = []
        for path in self.journal.directory.iterdir():
            if path.is_symlink() or not path.is_dir():
                continue
            data = self.journal.load(path.name)
            if data["status"] in {"committed", "restored"}:
                closed.append((data["created_at"], path))
        for _, path in sorted(closed, reverse=True)[keep:]:
            timer = self.root / "etc/systemd/system" / ("v6only-rollback-" + path.name + ".timer")
            if path.name not in protected and not timer.exists():
                shutil.rmtree(path)

    def recover(self, identifier, automatic=False):
        with self.locked():
            data = self.journal.load(identifier)
            state = self.read()
            if data["action"] == "dependencies":
                if state["dependency_pending"] not in {None, identifier}:
                    raise RuntimeError("存在不同依赖事务，拒绝恢复。")
                self._recover_dependencies(data)
                return {"status": "restored", "transaction": identifier, "mode": self.host.mode}
            if data["status"] == "restored":
                return {"status": "restored", "changed": False}
            if automatic and data["status"] == "committed":
                # 提交日志和运行状态之间崩溃：重放提交，不回滚已确认事务。
                if state["active_transaction"] == identifier:
                    self.write(data["after"])
                self.host.disarm(identifier)
                return {"status": "committed", "changed": False}
            if state["active_transaction"] not in {None, identifier}:
                raise RuntimeError("另一个事务正在进行，不能恢复指定事务。")
            if state["active_transaction"] is None and state["current_transaction"] != identifier:
                raise RuntimeError("只能撤销当前事务，不能覆盖较新的配置。")
            self._restore(data)
            return {"status": "restored", "transaction": identifier, "mode": self.host.mode}

    def guard(self):
        # 供 systemd 启动：不等待持有管理锁的父安装进程，只读取持久化状态。
        state = self.read()
        if state["active_transaction"]:
            data = self.journal.load(state["active_transaction"])
            state = data["before"] if data["status"] in {"restoring", "restore_failed"} else data["after"]
        if not state["enabled"]:
            raise RuntimeError("当前状态未启用，不安装网络规则。")
        content = (self.root / "etc/v6only/rules.nft").read_text()
        expected = self.hm.nft_config(state["policy"], state["nft_table"], state["backend"] == "singbox")
        if content != expected:
            raise RuntimeError("故障保护规则与当前策略不一致。", 5)
        actual = self.host.nft_snapshot(state["nft_table"])
        if actual is not None and actual != state["nft_snapshot"]:
            raise RuntimeError("同名 nftables 表不是当前已确认资源。", 5)
        if actual is None:
            self.host.nft_replace(state["nft_table"], content)
        if state["backend"] == "singbox":
            current_kernel = self.host.kernel_snapshot(state["policy"])
            expected = state["kernel_snapshot"] or {"rules": [], "routes": [], "addresses": []}
            if any(item not in expected[key] for key in current_kernel for item in current_kernel[key]):
                raise RuntimeError("专属路由范围存在未归属资源，拒绝覆盖。", 5)
            self.host.install_uid_rules(state["policy"])
        return {"enabled": True, "mode": self.host.mode}

    def status(self):
        state = self.read()
        result = {key: state[key] for key in ("installed", "enabled", "backend", "backend_version", "active_transaction", "dependency_pending")}
        result["mode"] = self.host.mode
        result["effective_enabled"] = state["enabled"]
        if state["active_transaction"]:
            data = self.journal.load(state["active_transaction"])
            result["transaction_status"] = data["status"]
            result["deadline"] = data["deadline"]
            if data["status"] in {"applying", "awaiting_confirm", "committed"}:
                result["effective_enabled"] = data["after"]["enabled"]
                result["effective_backend"] = data["after"]["backend"]
            elif data["status"] == "restore_failed":
                result["effective_enabled"] = "恢复失败，需诊断实际状态"
            # B7-fix: 为中断事务提供诊断指导
            if data["status"] in {"prepared", "rollback_armed", "restore_failed"}:
                result["说明"] = f"事务中断（状态：{data['status']}）。可执行：v6only confirm（提交）或 v6only rollback（恢复）。"
        return result

    def _diagnose_transaction(self, data):
        """只读诊断：输出事务状态下实时与期望的内核/防火墙资源。"""
        state = data.get("after") or data.get("before") or {}
        result = {"transaction": data["id"], "transaction_status": data["status"]}
        if data["status"] == "restore_failed":
            result["restore_failed"] = True
        try:
            result["kernel_live"] = self.host.kernel_snapshot(state["policy"]) if state.get("policy") else {}
            result["kernel_expected"] = state.get("kernel_snapshot") or {}
            if state.get("nft_table"):
                result["nft_live"] = self.host.nft_snapshot(state["nft_table"])
        except Exception as exc:  # 诊断本身不得抛出，避免再次卡死
            result["diagnostic_error"] = str(exc)
        return result


    def check(self):
        state = self.read()
        if state["dependency_pending"]:
            raise RuntimeError("依赖安装/恢复事务正在进行，暂不执行健康检查。")
        report = None
        if state["active_transaction"]:
            data = self.journal.load(state["active_transaction"])
            if data["status"] not in {"awaiting_confirm", "committed"}:
                # B7-fix: 中断事务返回诊断报告而不是卡死
                return {"ok": False, "diagnostic": True, **self._diagnose_transaction(data)}
            state, report = data["after"], data.get("before_report")
        if not state["installed"]:
            return {"ok": True, "installed": False, "说明": "没有已安装的运行组件，未执行网络探测。"}
        if self.owned_conflicts(state):
            raise RuntimeError("归属资源发生外部变化。", 5)
        result = self.host.health(state, report)
        self.records.append("health", "check", "成功" if result["ok"] else "失败", details=result)
        return result

    def retained_logs(self):
        path = self.root / "var/log/v6only/retained-resources.json"
        if not path.exists():
            return None
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("保留日志归属记录不安全。", 5)
        try:
            data = json.loads(path.read_text())
            if data["schema"] != "v6only-retained-logs-v1" or data["namespace"] != str(self.host.namespace_path()):
                raise ValueError
            return data
        except (ValueError, KeyError, TypeError):
            raise RuntimeError("保留日志归属记录无效。", 5)

    def purge(self, confirmed=False, keep_logs=False, remove_entry=False):
        if not confirmed:
            raise RuntimeError("清理不可恢复，需要显式 --yes；请先使用 --dry-run 审阅。")
        with self.locked():
            state = self.read()
            if state["installed"] or state["enabled"] or state["active_transaction"] or state["resources"]:
                raise RuntimeError("必须先完成并确认卸载、验证网络恢复，才能清理。")
            if state["current_transaction"]:
                data = self.journal.load(state["current_transaction"])
                if data["action"] != "uninstall" or data["status"] != "committed":
                    raise RuntimeError("当前记录不是已确认的卸载事务。")
            else:
                retained = self.retained_logs()
                if not retained:
                    raise RuntimeError("没有卸载成功记录，不能清理未知数据。")
                state.update(journal_owned=True, entry_sha256=retained["entry_sha256"], nft_table=retained["nft_table"])
            if state["nft_table"] and self.host.nft_snapshot(state["nft_table"]) is not None:
                raise RuntimeError("项目网络资源仍存在，停止清理。", 5)
            self.audit("purge", "开始", details={"keep_logs": keep_logs})
            # 配置和运行文件应已由卸载事务移除；未知文件不得被目录清理吞掉。
            paths = [self.root / "etc/v6only", self.root / "opt/v6only", self.directory]
            if not keep_logs:
                paths.append(self.root / "var/log/v6only")
            for path in paths:
                if path.is_symlink():
                    raise RuntimeError("清理路径出现符号链接，停止。", 5)
            for directory in paths[:2]:
                if directory.exists() and any(not path.is_dir() or path.is_symlink() for path in directory.rglob("*")):
                    raise RuntimeError("配置或运行目录包含未归属文件；未开始清理。", 5)
            allowed_state = {"runtime.json", "runtime.lock", "state.json", "write.lock", "transactions"}
            allowed_state.update(Path(path).name for path in state["mutable_resources"] if path == "/var/lib/v6only/singbox-cache.db")
            if any(path.name not in allowed_state or path.is_symlink() for path in self.directory.iterdir()):
                raise RuntimeError("数据目录包含未知资源，停止清理。", 5)
            transaction_directory = self.directory / "transactions"
            for directory in transaction_directory.iterdir() if transaction_directory.exists() else []:
                data = self.journal.load(directory.name)
                for extension in (".timer", ".service"):
                    unit_path = self.root / "etc/systemd/system" / ("v6only-rollback-" + directory.name + extension)
                    if unit_path.exists() or unit_path.is_symlink():
                        raise RuntimeError("仍有事务恢复单元残留，核实并清理对应任务后才能 purge。", 5)
                expected = {"journal.json", "timer-manifest.json"} | {f"{phase}-{i}" for i in range(len(data["resources"])) for phase in ("before", "after")}
                if any(path.name not in expected or path.is_symlink() or not path.is_file() for path in directory.iterdir()):
                    raise RuntimeError("事务目录包含未知资源，停止清理。", 5)
            logdir = self.root / "var/log/v6only"
            if not keep_logs and logdir.exists():
                import re
                if any(path.is_symlink() or not path.is_file() or not re.fullmatch(r"(?:audit|changes|health)-\d{8}\.jsonl|records\.lock|retained-resources\.json", path.name) for path in logdir.iterdir()):
                    raise RuntimeError("日志目录包含未知资源，停止清理。", 5)
            entry = self.root / "usr/local/sbin/v6only"
            if remove_entry and (entry.is_symlink() or not entry.is_file() or self.tx.digest(entry) != state["entry_sha256"]):
                raise RuntimeError("管理入口被修改，拒绝删除。", 5)
            if state["journal_owned"]:
                if keep_logs:
                    self.tx.atomic_json(logdir / "retained-resources.json", {"schema": "v6only-retained-logs-v1", "namespace": str(self.host.namespace_path()),
                                                                           "entry_sha256": state["entry_sha256"], "nft_table": state["nft_table"]})
                else:
                    self.host.remove_namespace()
            for path in paths:
                if path.exists():
                    shutil.rmtree(path)
            if remove_entry:
                entry.unlink()
            return {"purged": True, "kept_logs": keep_logs, "kept_entry": not remove_entry, "kept_dependencies": True,
                    "mode": self.host.mode, "说明": "只清理项目归属资源及专属日志；共享依赖保留，不清除全系统日志。"}

#!/usr/bin/env python3
"""在私有测试根目录静态验证 unit/timer；不启动 systemd 或后端。"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("v6only", ROOT / "src/lib/v6only.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

with tempfile.TemporaryDirectory(prefix="v6only-unit-verify-") as directory:
    root = Path(directory)
    units = root / "etc/systemd/system"
    units.mkdir(parents=True)
    manager = app.RUNTIME.Manager(app.HOST.SandboxHost(root), app.TRANSACTIONS, app.HOST, app.OBSERVABILITY,
                                  {"singbox": app.SINGBOX, "dnsmasq": app.DNSMASQ})
    policy = app.HOST.policy_defaults()
    policy.update(include_uids=[1000], dns_upstream="192.0.2.53", health_domains=["api.openai.com"])
    for backend in ("singbox", "dnsmasq"):
        files, _ = manager.files(backend, ["*.openai.com"], policy, b"static-path-fixture")
        for item in files:
            path = root / item["path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            content = item["content"]
            path.write_bytes(content.encode() if isinstance(content, str) else content)
            path.chmod(item.get("mode", 0o600))
    for name, content in app.HOST.rollback_units("a" * 32, "2099-01-01T00:00:00+00:00").items():
        (units / name).write_text(content)
    entry = root / "usr/local/sbin/v6only"
    entry.parent.mkdir(parents=True)
    entry.write_text("#!/bin/sh\nexit 0\n")
    entry.chmod(0o755)
    # 仅为分析器补齐依赖名称和可执行路径；这些占位对象从不运行。
    for name in ("sysinit", "basic", "shutdown", "network-online", "multi-user", "sockets", "timers"):
        (units / (name + ".target")).write_text("[Unit]\nDescription=static verification fixture\n")
    for name in ("systemd-journald@.socket", "systemd-journald-varlink@.socket"):
        (units / name).write_text("[Socket]\nListenDatagram=/run/fixture-%i.socket\n")
    for name in ("systemd-journald@.service", "systemd-journald-sync@.service"):
        (units / name).write_text("[Service]\nExecStart=/usr/local/sbin/v6only\n")
    candidates = sorted(str(path) for path in units.glob("v6only-*"))
    result = subprocess.run(["systemd-analyze", "verify", "--man=no", "--root=" + directory, *candidates], capture_output=True, text=True, timeout=30)
    print("仅静态验证项目 unit/timer 定义；依赖和二进制路径使用占位对象，没有启动任何服务。")
    print(result.stdout + result.stderr, end="")
    if result.returncode == 0:
        print(f"{len(candidates)} 个项目 unit/timer 静态验证通过。")
    sys.exit(result.returncode)

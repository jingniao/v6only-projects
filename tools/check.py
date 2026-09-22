#!/usr/bin/env python3
"""运行本地检查并保存真实输出；不安装依赖、不访问网络。"""
import datetime
import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description="本地开发检查；可选执行回环和隔离命名空间集成测试")
parser.add_argument("--integration", action="store_true", help="运行真实后端隔离测试，需已验证缓存和网络命名空间权限")
args = parser.parse_args()
RESULTS = ROOT / ".dev-state" / "results"
REPORT = ROOT / ".dev-state" / "test-results.md"
RESULTS.mkdir(parents=True, exist_ok=True)
os.chdir(ROOT)
env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
records = []
VERSION = re.search(r'^VERSION = "([^"]+)"', (ROOT / "src/lib/v6only.py").read_text(), re.MULTILINE).group(1)


def record(number, command, expected, action):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        success, output = action()
    except Exception as exc:
        success, output = False, f"{type(exc).__name__}: {exc}\n"
    (RESULTS / f"{number}.txt").write_text(output, encoding="utf-8")
    records.append((number, started, command, expected, success))
    print(f"{number}: {'通过' if success else '失败'}", flush=True)


def execute(argv, environment=None):
    completed = subprocess.run(argv, env=environment or env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    return completed.returncode == 0, completed.stdout


def deterministic_build():
    first = execute([sys.executable, "-B", "tools/build.py"])
    before = (ROOT / "dist/v6only").read_bytes()
    second = execute([sys.executable, "-B", "tools/build.py"])
    after = (ROOT / "dist/v6only").read_bytes()
    return first[0] and second[0] and before == after, first[1] + second[1] + f"构建内容一致：{before == after}\n"


record("B01", "python3 -B tools/build.py（执行两次并比较完整字节）", "两次构建完全一致", deterministic_build)
record("U01", "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/unit -v", "源码入口全部测试通过",
       lambda: execute([sys.executable, "-m", "unittest", "discover", "-s", "tests/unit", "-v"], dict(env, V6ONLY_TEST_ENTRY=str(ROOT / "src/v6only.sh"))))
record("U02", 'V6ONLY_TEST_ENTRY="$PWD/dist/v6only" PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/unit -v',
       "单文件入口全部测试通过",
       lambda: execute([sys.executable, "-m", "unittest", "discover", "-s", "tests/unit", "-v"], dict(env, V6ONLY_TEST_ENTRY=str(ROOT / "dist/v6only"))))


def static_checks():
    output = []
    success = True
    for path in ("src/v6only.sh", "dist/v6only"):
        passed, result = execute(["bash", "-n", path])
        success = success and passed
        output.append(f"bash -n {path}: {'通过' if passed else '失败'}\n{result}")
    for path in sorted(ROOT.rglob("*.py")):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
        output.append(f"Python 语法检查：{path.relative_to(ROOT)} 通过\n")
    return success, "".join(output)


record("S01", "bash -n（两个入口）；compile()（全部 Python 源码，不生成 pyc）", "语法检查通过", static_checks)
if shutil.which("systemd-analyze"):
    record("S03", "python3 -B tools/check_units.py", "私有测试根目录中 unit/timer 静态验证通过，不启动服务",
           lambda: execute([sys.executable, "-B", "tools/check_units.py"]))


def mask_code(text):
    """链接扫描前屏蔽围栏代码块与行内代码；其中的正则片段不是导航链接。"""
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return re.sub(r"`[^`\n]*`", "", text)


def doc_checks():
    errors = []
    # 本机报告在本次检查结束后生成到 .dev-state/，其中链接指向同目录结果。
    for path in ROOT.rglob("*.md"):
        if {ROOT / ".dev-state", ROOT / ".cache", ROOT / ".git"} & set(path.parents):
            # 本机运行产物与依赖缓存不属于仓库导航。
            continue
        for target in re.findall(r"\]\(([^)]+)\)", mask_code(path.read_text(encoding="utf-8"))):
            if "://" in target or target.startswith("#"):
                continue
            destination = (path.parent / target.split("#")[0]).resolve()
            if destination == REPORT:
                continue
            if not destination.exists():
                errors.append(f"失效链接：{path.relative_to(ROOT)} → {target}")
    original = ROOT.parent / "PROJECT_SPEC.md"
    if original.exists() and original.read_bytes() != (ROOT / "PROJECT_SPEC.md").read_bytes():
        errors.append("规范副本与原文件不同")
    return not errors, "\n".join(errors) + ("\n" if errors else "本地文档链接与原始规范副本检查通过。\n")


record("D01", "检查 Markdown 本地链接及 PROJECT_SPEC.md 副本", "文档无失效本地链接，规范副本不变", doc_checks)

official = (ROOT / ".cache/sing-box-1.14.1/sing-box").is_file()
if official:
    record("C01", "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/static -v",
           "官方 sing-box 1.14.1 接受候选变体并拒绝无效配置；不启动网络服务",
           lambda: execute([sys.executable, "-m", "unittest", "discover", "-s", "tests/static", "-v"]))

if args.integration:
    record("I01", "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/integration -p test_dnsmasq.py -v",
           "真实 dnsmasq 回环测试通过；未改变系统 DNS",
           lambda: execute([sys.executable, "-m", "unittest", "discover", "-s", "tests/integration", "-p", "test_dnsmasq.py", "-v"]))
    record("I02", "PYTHONDONTWRITEBYTECODE=1 python3 tests/integration/test_tun_namespace.py",
           "独立网络命名空间内 TUN、TCP/TLS/UDP、故障与恢复场景通过；默认命名空间不变",
           lambda: execute([sys.executable, "-B", "tests/integration/test_tun_namespace.py"]))

shellcheck = shutil.which("shellcheck")
if shellcheck:
    record("S02", "shellcheck src/v6only.sh dist/v6only", "ShellCheck 通过",
           lambda: execute([shellcheck, "src/v6only.sh", "dist/v6only"]))

report = ["# 实际测试记录\n", f"软件版本：{VERSION}。环境：{platform.platform()}；Python {platform.python_version()}。\n",
          "测试数据写入临时目录并清理；结果记录、构建产物写入工作区。未安装系统软件包或创建宿主机服务，未修改宿主机 DNS、路由、防火墙及网卡配置。回环测试仅临时监听高端口，TUN 等配置变更只发生在独立网络命名空间。\n",
          "生命周期、APT 和 systemd 调度的单元测试使用模拟宿主机；不能替代目标服务器的完整安装和重启验收。\n"]
for number, started, command, expected, success in records:
    raw = (RESULTS / f"{number}.txt").read_text(encoding="utf-8")
    count = re.search(r"Ran (\d+) tests?", raw)
    report.extend([f"## {number}\n", f"执行时间（UTC）：{started}\n", f"执行命令：`{command}`\n",
                   f"预期：{expected}。\n", f"结论：{'通过' if success else '失败'}" + (f"，{count.group(1)} 项测试" if count else "") + "。\n",
                   f"[完整实际输出](results/{number}.txt)\n"])
report += ["## 限制与未执行项\n",
           ("ShellCheck 已执行，见 S02。\n" if shellcheck else "ShellCheck 未执行：当前环境没有安装该工具，未安装任何新依赖。\n"),
           ("sing-box 1.14.1 官方配置构造校验已执行，见 C01。\n" if official else "sing-box 官方配置校验未执行：本地缓存无校验器，没有自动下载。\n"),
           ("真实 dnsmasq 配置/回环 DNS、隔离 TUN 的 TCP/TLS/UDP 和故障测试已执行，见 I01/I02；[命名空间内逐项输出](results/tun-namespace-details.txt)。\n" if args.integration else "本次未执行回环 DNS 和独立网络命名空间集成测试。\n"),
           "目标服务器真实 SSH、DynamicV6 服务多轮运行、真实 systemd 定时恢复、APT 安装、完整系统生命周期及重启验收未执行。隔离测试中的策略更新是受控模拟，不是运行真实 DynamicV6。\n",
           "源码与发行入口共用同一套单元用例；两次通过不代表两套独立网络验证。最低 Python 版本和其他发行版兼容性尚未实测。\n",
           f"单文件产物 SHA-256：`{hashlib.sha256((ROOT / 'dist/v6only').read_bytes()).hexdigest()}`。\n"]
REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text("\n".join(report), encoding="utf-8")
sys.exit(0 if all(row[-1] for row in records) else 1)

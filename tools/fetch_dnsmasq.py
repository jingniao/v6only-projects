#!/usr/bin/env python3
"""提取固定的 Debian dnsmasq-base 开发测试包，不执行安装或维护脚本。"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description="仅下载提取已锁定的 dnsmasq 2.91 测试二进制")
    parser.add_argument("--dry-run", action="store_true", help="只显示计划，不联网或写文件")
    args = parser.parse_args()
    lock = json.loads((ROOT / "tools/dnsmasq-release.json").read_text())
    directory = ROOT / ".cache/dnsmasq-2.91"
    print("计划：从 Debian 官方地址下载并验证 SHA-256，使用 dpkg-deb -x 提取到项目缓存。")
    print(lock["url"])
    print("不会运行 apt install、dpkg -i、维护脚本或系统服务；该二进制需要兼容的本机共享库。")
    if args.dry_run:
        return
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise SystemExit("下载锁仅适用于 Linux amd64。")
    if directory.exists() or any(path.is_symlink() for path in [directory, *directory.parents]):
        raise SystemExit("目标已存在或路径含符号链接，拒绝覆盖。")
    with urllib.request.urlopen(lock["url"], timeout=30) as response:
        archive = response.read(5 * 1024 * 1024 + 1)
    if hashlib.sha256(archive).hexdigest() != lock["sha256"]:
        raise SystemExit("官方软件包摘要不符，未提取或执行。")
    directory.mkdir(parents=True, mode=0o700)
    package = directory / "dnsmasq.deb"
    package.write_bytes(archive)
    subprocess.run(["dpkg-deb", "-x", str(package), str(directory / "extracted")], check=True)
    binary = directory / "extracted/usr/sbin/dnsmasq"
    if hashlib.sha256(binary.read_bytes()).hexdigest() != lock["binary_sha256"]:
        raise SystemExit("提取后二进制摘要不符，未执行。")
    print("官方包与二进制摘要验证通过。")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""显式下载已锁定的静态校验工具到项目缓存，不安装或启动服务。"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description="下载 sing-box 1.14.1 到项目缓存，仅供静态校验")
    parser.add_argument("--dry-run", action="store_true", help="仅显示联网计划，不下载或写入")
    args = parser.parse_args()
    lock = json.loads((ROOT / "tools/singbox-release.json").read_text())
    directory = ROOT / ".cache/sing-box-1.14.1"
    destination = directory / "sing-box"
    print(f"计划：从官方发布地址下载 {lock['archive_url']}，校验 SHA-256 后保存到 {destination}。", flush=True)
    print("不安装到系统 PATH，不创建服务，不执行 sing-box run。", flush=True)
    if args.dry_run:
        return
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise SystemExit("当前下载锁只覆盖 Linux amd64，拒绝下载不匹配的架构。")
    if directory.exists():
        raise SystemExit("缓存目录已存在；请核实已有内容，工具不会覆盖。")
    with urllib.request.urlopen(lock["archive_url"], timeout=60) as response:
        archive = response.read(100 * 1024 * 1024 + 1)
    if len(archive) > 100 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != lock["archive_sha256"]:
        raise SystemExit("官方归档大小或摘要不符，未提取或执行。")
    # 只读取预期的普通文件，不使用 extractall，不信任归档路径或链接。
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        member = bundle.getmember(lock["archive_member"])
        if not member.isfile() or member.size > 160 * 1024 * 1024:
            raise SystemExit("归档内二进制不是预期的普通文件。")
        binary = bundle.extractfile(member).read()
    directory.mkdir(parents=True, mode=0o700)
    with destination.open("xb") as stream:
        stream.write(binary)
    destination.chmod(0o700)
    metadata = {**lock, "binary_sha256": hashlib.sha256(binary).hexdigest()}
    (directory / "verified.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    print(f"归档摘要验证通过；二进制 SHA-256：{metadata['binary_sha256']}")


if __name__ == "__main__":
    main()

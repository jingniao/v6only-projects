"""私有审计、健康记录与容量/保留期管理。"""
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import time


def redact(value):
    if isinstance(value, dict):
        return {key: ("[已脱敏]" if re.search(r"authorization|cookie|api.?key|token|password|secret", key, re.I) else redact(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(x) for x in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(Authorization|Cookie|api[_-]?key|token|password)\s*[:=]\s*[^\s,;]+(?:\s+[^\s,;]+)?", r"\1=[已脱敏]", value)
        value = re.sub(r"https?://[^\s]+", "[URL 已脱敏]", value)
        value = re.sub(r"\bsk-[A-Za-z0-9_-]+", "[密钥已脱敏]", value)
        return value[:4096]
    return value


class Records:
    def __init__(self, directory, limit=100 * 1024 * 1024):
        self.directory = Path(directory)
        self.limit = limit

    def append(self, kind, action, result, transaction=None, details=None):
        if kind not in {"audit", "changes", "health"}:
            raise ValueError("未知日志类别")
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_uid != os.geteuid() or self.directory.stat().st_mode & 0o077:
            raise PermissionError("日志目录必须由当前用户私有")
        lock = os.open(self.directory / "records.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock, "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            self._append_locked(kind, action, result, transaction, details)

    def _append_locked(self, kind, action, result, transaction, details):
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        record = {"time": timestamp.isoformat(), "uid": os.geteuid(), "action": action,
                  "transaction": transaction, "result": result, "details": redact(details or {})}
        path = self.directory / f"{kind}-{timestamp:%Y%m%d}.jsonl"
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.prune(timestamp)

    def prune(self, timestamp=None):
        timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc)
        entries = []
        for path in self.directory.glob("*.jsonl"):
            match = re.fullmatch(r"(audit|changes|health)-(\d{8})\.jsonl", path.name)
            if not match or path.is_symlink():
                continue
            date = datetime.datetime.strptime(match.group(2), "%Y%m%d").replace(tzinfo=datetime.timezone.utc)
            if (timestamp - date).days >= (90 if match.group(1) == "health" else 30):
                path.unlink()
            else:
                entries.append(path)
        total = sum(path.stat().st_size for path in entries)
        for path in sorted(entries, key=lambda p: (p.name.split("-")[-1], p.name)):
            if total <= self.limit:
                break
            size = path.stat().st_size
            if len(entries) == 1:
                # 保留末尾完整记录，不触及事务快照或系统 journal。
                data = path.read_bytes()[-self.limit:]
                data = data[data.find(b"\n") + 1:]
                temporary = path.with_suffix(".rotate")
                fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                os.replace(temporary, path)
                break
            path.unlink()
            entries.remove(path)
            total -= size

    def read(self, kind=None, limit=100):
        records = []
        if not self.directory.exists():
            return records
        for path in sorted(self.directory.glob("*.jsonl")):
            if path.is_symlink() or not re.fullmatch(r"(audit|changes|health)-\d{8}\.jsonl", path.name):
                continue
            if kind and not path.name.startswith(kind + "-"):
                continue
            for line in path.read_text().splitlines():
                try:
                    record = json.loads(line)
                    if isinstance(record, dict) and isinstance(record.get("time"), str):
                        records.append(record)
                except ValueError:
                    continue
        return sorted(records, key=lambda x: x["time"])[-limit:]


def network_test(domain, timeout=5):
    """DNS、TCP/TLS、HTTP 权限分开报告；不使用凭据。"""
    started = time.monotonic()
    report = {"domain": domain, "dns": {}, "tcp_tls": [], "business_access": "未判定；HTTP 401/403 不直接等于网络故障"}
    # getaddrinfo 无原生期限；调用者应在有总期限的独立进程中运行。
    for family, name in ((socket.AF_INET6, "AAAA"), (socket.AF_INET, "A")):
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, 443, family, socket.SOCK_STREAM)})
            report["dns"][name] = addresses
        except socket.gaierror:
            report["dns"][name] = []
    context = ssl.create_default_context()
    for address in report["dns"].get("AAAA", [])[:3]:
        entry = {"address": address, "family": "IPv6", "ok": False}
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as stream:
                stream.settimeout(timeout)
                stream.connect((address, 443))
                with context.wrap_socket(stream, server_hostname=domain) as tls:
                    entry.update(ok=True, tls=tls.version())
        except (OSError, ssl.SSLError) as exc:
            entry["error_category"] = type(exc).__name__
        report["tcp_tls"].append(entry)
    report["ipv6_available"] = any(item["ok"] for item in report["tcp_tls"])
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["limitation"] = "这是指定进程的 DNS/TLS 检查，不等于 TUN 接管、业务权限或全故障场景验收。"
    return report

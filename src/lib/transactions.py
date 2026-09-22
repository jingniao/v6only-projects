"""持久化文件事务：写前日志、唯一事务、冲突检测、幂等恢复。"""
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import uuid


class TransactionError(Exception):
    def __init__(self, message, code=4):
        super().__init__(message)
        self.code = code


def digest(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def atomic_json(path, data):
    payload = (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    atomic_bytes(path, payload, 0o600)


def atomic_bytes(path, payload, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".v6only-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def allowed(path):
    original = str(path)
    path = PurePosixPath(path)
    value = str(path)
    if original != value or not path.is_absolute() or ".." in path.parts or "\x00" in value:
        return False
    if value in {"/usr/local/sbin/v6only", "/etc/systemd/journald@v6only.conf", "/usr/sbin/policy-rc.d",
                 "/etc/systemd/system/systemd-journald@v6only.service.d/v6only.conf"}:
        return True
    if value.startswith(("/etc/v6only/", "/opt/v6only/")):
        return True
    return (path.parent == PurePosixPath("/etc/systemd/system") and path.name.startswith("v6only-")
            and path.suffix in {".service", ".timer"})


class Journal:
    def __init__(self, root, directory):
        self.root = Path(root).absolute()
        self.directory = Path(directory)

    def target(self, path):
        if not allowed(path):
            raise TransactionError("资源不在项目允许管理的路径范围内。", 3)
        target = self.root / str(PurePosixPath(path)).lstrip("/")
        for parent in [target, *target.parents]:
            if parent == self.root.parent:
                break
            if parent.is_symlink():
                raise TransactionError("项目资源路径含符号链接；拒绝跟随或覆盖。", 3)
        return target

    def inspect(self, path):
        target = self.target(path)
        if not target.exists():
            return {"exists": False}
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise TransactionError("资源必须为非硬链接的普通文件。", 3)
        try:
            if os.listxattr(target, follow_symlinks=False):
                raise TransactionError("资源含扩展属性或 ACL，当前版本拒绝自动覆盖以免丢失元数据。", 3)
        except OSError as exc:
            if exc.errno not in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise TransactionError("无法读取资源扩展元数据，拒绝自动修改。", 3)
        return {"exists": True, "sha256": digest(target), "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid, "gid": info.st_gid}

    def create(self, action, changes, before, after, ttl=180):
        """在任何目标文件修改之前保存完整恢复快照和预期摘要。"""
        if not 30 <= ttl <= 3600:
            raise TransactionError("确认期限必须为 30–3600 秒。", 2)
        paths = [item["path"] for item in changes]
        if len(paths) != len(set(paths)):
            raise TransactionError("事务中出现重复资源。")
        identifier = uuid.uuid4().hex
        directory = self.directory / identifier
        directory.mkdir(parents=True, mode=0o700)
        resources = []
        for index, item in enumerate(changes):
            path, payload = item["path"], item.get("content")
            original = self.inspect(path)
            if original["exists"]:
                snapshot = directory / f"before-{index}"
                shutil.copyfile(self.target(path), snapshot)
                snapshot.chmod(0o600)
                with snapshot.open("rb") as stream:
                    os.fsync(stream.fileno())
                if digest(snapshot) != original["sha256"] or self.inspect(path) != original:
                    raise TransactionError("保存快照期间资源发生变化；未修改目标文件。")
            if payload is None:
                desired = {"exists": False}
            else:
                if isinstance(payload, str):
                    payload = payload.encode()
                atomic_bytes(directory / f"after-{index}", payload)
                desired = {"exists": True, "sha256": hashlib.sha256(payload).hexdigest(),
                           "mode": item.get("mode", 0o600), "uid": os.geteuid(), "gid": os.getegid()}
            resources.append({"path": path, "before": original, "after": desired, "transient": item.get("transient", False)})
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        data = {"schema": 1, "id": identifier, "action": action, "status": "prepared",
                "created_at": timestamp.isoformat(), "deadline": (timestamp + datetime.timedelta(seconds=ttl)).isoformat(),
                "before": before, "after": after, "resources": resources}
        atomic_json(directory / "journal.json", data)
        return data

    def load(self, identifier):
        if not isinstance(identifier, str) or len(identifier) != 32 or any(x not in "0123456789abcdef" for x in identifier):
            raise TransactionError("无效的事务标识。", 2)
        path = self.directory / identifier / "journal.json"
        if path.is_symlink():
            raise TransactionError("事务日志路径异常。", 5)
        try:
            data = json.loads(path.read_text())
            if data["schema"] != 1 or data["id"] != identifier or not isinstance(data["resources"], list):
                raise ValueError
            if data["status"] not in {"prepared", "rollback_armed", "applying", "awaiting_confirm", "committed", "restoring", "restored", "restore_failed"}:
                raise ValueError
            if datetime.datetime.fromisoformat(data["deadline"]).tzinfo is None or not isinstance(data["before"], dict) or not isinstance(data["after"], dict):
                raise ValueError
            seen = set()
            for item in data["resources"]:
                if item["path"] in seen or not allowed(item["path"]):
                    raise ValueError
                seen.add(item["path"])
                for phase in ("before", "after"):
                    signature = item[phase]
                    if type(signature["exists"]) is not bool:
                        raise ValueError
                    if signature["exists"] and (not isinstance(signature["sha256"], str) or len(signature["sha256"]) != 64 or signature["mode"] & ~0o777):
                        raise ValueError
            return data
        except (OSError, ValueError, KeyError, TypeError):
            raise TransactionError("事务日志损坏或不存在；保留恢复资料。", 5)

    def save(self, data, status=None):
        if status is not None:
            data["status"] = status
        atomic_json(self.directory / data["id"] / "journal.json", data)

    def conflicts(self, data, accept_before=False):
        conflicts = []
        for item in data["resources"]:
            current = self.inspect(item["path"])
            if current != item["after"] and not ((accept_before or item.get("transient")) and current == item["before"]):
                conflicts.append(item["path"])
        return conflicts

    def apply_files(self, data, fault=None):
        # 安排独立回滚由调用方完成；日志状态是必需前置条件。
        if data["status"] != "rollback_armed":
            raise TransactionError("独立回滚尚未安排，拒绝修改资源。", 3)
        for item in data["resources"]:
            if self.inspect(item["path"]) != item["before"]:
                raise TransactionError("临时应用前发现外部资源变更。")
        self.save(data, "applying")
        for index, item in enumerate(data["resources"]):
            self._write_snapshot(data, index, "after")
            if fault:
                fault(index)

    def _write_snapshot(self, data, index, phase):
        item = data["resources"][index]
        target, signature = self.target(item["path"]), item[phase]
        if not signature["exists"]:
            if target.exists():
                target.unlink()
                fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return
        source = self.directory / data["id"] / f"{phase}-{index}"
        if source.is_symlink() or not source.is_file() or digest(source) != signature["sha256"]:
            raise TransactionError("恢复快照摘要不匹配；未覆盖资源。", 5)
        atomic_bytes(target, source.read_bytes(), signature["mode"])
        if (signature["uid"], signature["gid"]) != (os.geteuid(), os.getegid()):
            os.chown(target, signature["uid"], signature["gid"])

    def restore_files(self, data):
        conflicts = self.conflicts(data, accept_before=True)
        if conflicts:
            self.save(data, "restore_failed")
            raise TransactionError("发现用户后续修改，停止恢复并保留快照：" + ", ".join(conflicts), 5)
        # 先验证全部所需快照，避免中途才发现唯一备份损坏。
        for index, item in enumerate(data["resources"]):
            if item["before"]["exists"]:
                source = self.directory / data["id"] / f"before-{index}"
                if source.is_symlink() or not source.is_file() or digest(source) != item["before"]["sha256"]:
                    self.save(data, "restore_failed")
                    raise TransactionError("恢复快照缺失或损坏；未开始文件恢复。", 5)
        self.save(data, "restoring")
        for index in reversed(range(len(data["resources"]))):
            self._write_snapshot(data, index, "before")

    def confirmable(self, data, timestamp=None):
        if data["status"] != "awaiting_confirm":
            raise TransactionError("当前事务不处于待确认状态。", 3)
        timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc)
        if timestamp >= datetime.datetime.fromisoformat(data["deadline"]):
            raise TransactionError("确认期限已过；必须恢复，不能提交。", 3)
        if self.conflicts(data):
            raise TransactionError("待确认资源已被外部修改，拒绝提交。", 5)

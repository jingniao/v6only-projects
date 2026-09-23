#!/usr/bin/env python3
"""Persist the complete v6only operational state into SQLite.

The JSON files remain the transactional source of truth. This database is a
root-only durable archive/query store: every collected file is versioned by
sha256 and every runtime observation is timestamped.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(os.environ.get("V6ONLY_PERSIST_ROOT", "/"))
DB = pathlib.Path(os.environ.get("V6ONLY_PERSIST_DB", "/var/lib/v6only/v6only.db"))
STATE = ROOT / "var/lib/v6only"
ETC = ROOT / "etc/v6only"
# v6only/dynamicv6/UFW/networking 的完整持久化范围；数据库自身明确排除。
FILE_ROOTS = [
    ROOT / "var/lib/v6only",
    ROOT / "etc/v6only",
    ROOT / "etc/dynamicv6-next",
    ROOT / "var/lib/dynamicv6-next-guest",
    ROOT / "etc/ufw",
    ROOT / "etc/network",
    ROOT / "etc/cloud/cloud.cfg.d",
    ROOT / "etc/systemd/system",
]
LOG_DIRS = [ROOT / "var/log/v6only", ROOT / "var/log/v6only-manager"]
HOSTNAME = ROOT / "etc/hostname"


def now():
    return datetime.now(timezone.utc).isoformat()


def run(*args, timeout=20):
    try:
        p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout
    except Exception as exc:
        return 127, f"{type(exc).__name__}: {exc}\n"


def sha(data: bytes):
    return hashlib.sha256(data).hexdigest()


def json_load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def init_db(con):
    con.executescript("""
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=FULL;
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      path TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      size INTEGER NOT NULL,
      mtime_ns INTEGER,
      content BLOB NOT NULL,
      collected_at TEXT NOT NULL,
      UNIQUE(path, sha256)
    );
    CREATE INDEX IF NOT EXISTS files_path_time ON files(path, collected_at);
    CREATE TABLE IF NOT EXISTS snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      collected_at TEXT NOT NULL,
      hostname TEXT,
      source TEXT NOT NULL,
      payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS rules (
      snapshot_id INTEGER NOT NULL,
      domain TEXT NOT NULL,
      PRIMARY KEY(snapshot_id, domain),
      FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS runtime (
      snapshot_id INTEGER PRIMARY KEY,
      installed INTEGER, enabled INTEGER, backend TEXT,
      backend_version TEXT, active_transaction TEXT,
      revision INTEGER, policy_json TEXT, raw_json TEXT NOT NULL,
      FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      source_file TEXT,
      event_time TEXT,
      action TEXT,
      revision INTEGER,
      transaction_id TEXT,
      result TEXT,
      payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      transaction_id TEXT,
      path TEXT NOT NULL,
      status TEXT,
      payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS health_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      source TEXT NOT NULL,
      ok INTEGER,
      services INTEGER, nft INTEGER, route INTEGER,
      dns_tcp_tls INTEGER, ssh_route INTEGER,
      payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ufw_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      active INTEGER,
      status_text TEXT NOT NULL,
      added_rules TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS network_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      addresses TEXT NOT NULL,
      rules TEXT NOT NULL,
      routes TEXT NOT NULL,
      listeners TEXT NOT NULL,
      interfaces TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS aaaa_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      domain TEXT NOT NULL,
      addresses TEXT NOT NULL,
      ok INTEGER NOT NULL,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS aaaa_domain_time ON aaaa_checks(domain, observed_at);
    CREATE TABLE IF NOT EXISTS command_outputs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observed_at TEXT NOT NULL,
      command TEXT NOT NULL,
      exit_code INTEGER NOT NULL,
      output TEXT NOT NULL
    );
    """)


def collect_files(con, observed):
    paths = []
    for base in FILE_ROOTS:
        if base.exists():
            paths.extend(p for p in base.rglob("*") if p.is_file() and not p.is_socket())
    for base in LOG_DIRS:
        if base.exists():
            paths.extend(p for p in base.rglob("*") if p.is_file() and p.stat().st_size <= 20 * 1024 * 1024)
    for path in sorted(set(paths)):
        try:
            # 不把 SQLite 数据库、WAL 或 SHM 归档进自己。
            if path == DB or str(path).startswith(str(DB) + "-"):
                continue
            data = path.read_bytes()
            st = path.stat()
            rel = "/" + str(path.relative_to(ROOT))
            digest = sha(data)
            con.execute("""INSERT OR IGNORE INTO files
                (path,sha256,size,mtime_ns,content,collected_at)
                VALUES (?,?,?,?,?,?)""",
                (rel, digest, len(data), st.st_mtime_ns, data, observed))
        except (OSError, ValueError):
            continue


def record_snapshot(con, observed, runtime, state):
    hostname = HOSTNAME.read_text(errors="replace").strip() if HOSTNAME.exists() else socket.gethostname()
    domains = sorted(set((runtime or {}).get("domains", []) or (state or {}).get("domains", [])))
    payload = json.dumps({"runtime": runtime, "state": state}, ensure_ascii=False, sort_keys=True)
    cur = con.execute("INSERT INTO snapshots(collected_at,hostname,source,payload) VALUES(?,?,?,?)",
                      (observed, hostname, "v6only", payload))
    sid = cur.lastrowid
    for domain in domains:
        con.execute("INSERT INTO rules(snapshot_id,domain) VALUES(?,?)", (sid, domain))
    policy = (runtime or {}).get("policy") or {}
    con.execute("""INSERT INTO runtime
      (snapshot_id,installed,enabled,backend,backend_version,active_transaction,
       revision,policy_json,raw_json) VALUES(?,?,?,?,?,?,?,?,?)""",
      (sid, int(bool((runtime or {}).get("installed"))), int(bool((runtime or {}).get("enabled"))),
       (runtime or {}).get("backend"), (runtime or {}).get("backend_version"),
       (runtime or {}).get("active_transaction"), (state or {}).get("revision"),
       json.dumps(policy, ensure_ascii=False, sort_keys=True),
       json.dumps({"runtime": runtime, "state": state}, ensure_ascii=False, sort_keys=True)))
    for event in (state or {}).get("events", []):
        con.execute("""INSERT OR IGNORE INTO events
          (observed_at,source_file,event_time,action,revision,transaction_id,result,payload)
          VALUES(?,?,?,?,?,?,?,?)""",
          (observed, "/var/lib/v6only/state.json", event.get("time"), event.get("action"),
           event.get("revision"), event.get("transaction"), event.get("result"),
           json.dumps(event, ensure_ascii=False, sort_keys=True)))
    for path in sorted(STATE.glob("transactions/**/journal.json")):
        obj = json_load(path)
        if obj is not None:
            con.execute("""INSERT INTO transactions
              (observed_at,transaction_id,path,status,payload) VALUES(?,?,?,?,?)""",
              (observed, path.parent.name, "/" + str(path.relative_to(ROOT)),
               obj.get("status") if isinstance(obj, dict) else None,
               json.dumps(obj, ensure_ascii=False, sort_keys=True)))
    return sid, domains


def command_snapshot(con, observed, args):
    code, out = run(*args)
    con.execute("INSERT INTO command_outputs(observed_at,command,exit_code,output) VALUES(?,?,?,?)",
                (observed, " ".join(args), code, out))
    return out


def record_runtime_checks(con, observed, runtime, domains):
    code, out = run("/usr/local/sbin/v6only", "check")
    try:
        obj = json.loads(out)
    except Exception:
        obj = {"raw": out}
    con.execute("""INSERT INTO health_checks
      (observed_at,source,ok,services,nft,route,dns_tcp_tls,ssh_route,payload)
      VALUES(?,?,?,?,?,?,?,?,?)""",
      (observed, "v6only check", int(bool(obj.get("ok"))),
       int(bool(obj.get("services"))), int(bool(obj.get("nft"))), int(bool(obj.get("route"))),
       int(bool(obj.get("dns_tcp_tls"))), int(bool(obj.get("ssh_route"))),
       json.dumps(obj, ensure_ascii=False, sort_keys=True)))
    status = command_snapshot(con, observed, ["ufw", "status", "verbose"])
    added = command_snapshot(con, observed, ["ufw", "show", "added"])
    con.execute("INSERT INTO ufw_checks(observed_at,active,status_text,added_rules) VALUES(?,?,?,?)",
                (observed, int("Status: active" in status), status, added))
    addresses = command_snapshot(con, observed, ["ip", "-j", "-6", "addr", "show"])
    rules = command_snapshot(con, observed, ["ip", "-j", "-6", "rule", "show"])
    routes = command_snapshot(con, observed, ["ip", "-j", "-6", "route", "show", "table", "all"])
    listeners = command_snapshot(con, observed, ["ss", "-lntup"])
    interfaces = command_snapshot(con, observed, ["ip", "-j", "link", "show"])
    con.execute("""INSERT INTO network_snapshots
      (observed_at,addresses,rules,routes,listeners,interfaces) VALUES(?,?,?,?,?,?)""",
      (observed, addresses, rules, routes, listeners, interfaces))
    for domain in domains:
        code, out = run("getent", "ahostsv6", domain)
        found = sorted({line.split()[0] for line in out.splitlines() if line.split()})
        # getent may print IPv4-mapped results; keep only real IPv6 values.
        found = [x for x in found if ":" in x and not x.lower().startswith("::ffff:")]
        con.execute("""INSERT INTO aaaa_checks
          (observed_at,domain,addresses,ok,error) VALUES(?,?,?,?,?)""",
          (observed, domain, json.dumps(found), int(bool(found)), None if found else out[-1000:]))


def main():
    DB.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    con = sqlite3.connect(DB)
    try:
        init_db(con)
        observed = now()
        runtime = json_load(STATE / "runtime.json") or {}
        state = json_load(STATE / "state.json") or {}
        with con:
            collect_files(con, observed)
            sid, domains = record_snapshot(con, observed, runtime, state)
            record_runtime_checks(con, observed, runtime, domains)
            con.execute("INSERT OR REPLACE INTO meta(key,value,updated_at) VALUES(?,?,?)",
                        ("last_snapshot_id", str(sid), observed))
            con.execute("INSERT OR REPLACE INTO meta(key,value,updated_at) VALUES(?,?,?)",
                        ("last_collected_at", observed, observed))
            con.execute("INSERT OR REPLACE INTO meta(key,value,updated_at) VALUES(?,?,?)",
                        ("schema_version", "1", observed))
        os.chmod(DB, 0o600)
        # Make WAL/SHM root-only as well when present.
        for suffix in ("-wal", "-shm"):
            p = pathlib.Path(str(DB) + suffix)
            if p.exists():
                os.chmod(p, 0o600)
        print(json.dumps({"ok": True, "database": str(DB), "snapshot_id": sid,
                          "rules": len(domains), "collected_at": observed}, ensure_ascii=False))
    finally:
        con.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"persistence failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise

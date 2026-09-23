#!/usr/bin/env bash
# v6only 一键安装/修复器
# 目标：Debian 12/13、Ubuntu 22.04/24.04、systemd、amd64
# 默认：sing-box 1.14.1 + DoH + UID 1500 + google.com 健康检查
set -euo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SELF_DIR/.." && pwd)"
ENTRY="$ROOT_DIR/dist/v6only"
STATE_DIR="/var/lib/v6only"
RUN_USER="v6only-run"
RUN_UID="1500"
DNS_UPSTREAM="https://dns.google/dns-query?bootstrap=2001:4860:4860::8844"
HEALTH_DOMAIN="google.com"
POLICY_FILE="/run/v6only-oneclick-policy.json"
DOMAINS_FILE="/run/v6only-oneclick-domains.txt"
DRY_RUN=0
SKIP_TESTS=0
SSH_PEER_OVERRIDE=""

DOMAINS=(
  '*.auth0.com'
  '*.challenges.cloudflare.com'
  '*.chatgpt.com'
  '*.grok.com'
  '*.identrust.com'
  '*.oaistatic.com'
  '*.openai.com'
  '*.sora.com'
  '*.x.ai'
  'auth0.com'
  'challenges.cloudflare.com'
  'chatgpt.com'
  'client-api.arkoselabs.com'
  'grok.com'
  'identrust.com'
  'oaistatic.com'
  'openaiapi-site.azureedge.net'
  'sora.com'
  'x.ai'
)

usage() {
  cat <<'EOF'
用法：sudo bash tools/install-oneclick.sh [选项]

选项：
  --dry-run       只检查、构建、生成策略并显示计划，不安装或修改网络
  --skip-tests    跳过本地项目测试（不建议）
  --source DIR    指定 v6only 项目目录，默认使用脚本所在项目目录
  --ssh-peer IP   指定真实 SSH 管理端 IP（适用于 Netcatty/跳板代理）
  -h, --help      显示帮助

默认行为：
  创建/校验 v6only-run UID 1500；
  使用 sing-box 1.14.1；
  使用 Google DoH（IPv6 bootstrap）；
  使用 google.com 做健康检查；
  安装 19 条 IPv6-only 分流规则；
  不启用 UFW、不重启、不修改主机公网 IPv6。
EOF
}

say() { printf '\n[%s] %s\n' "$(date '+%F %T')" "$*"; }
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "缺少命令：$1"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --source)
      [ "$#" -ge 2 ] || fail "--source 需要目录"
      ROOT_DIR="$2"; ENTRY="$ROOT_DIR/dist/v6only"; shift 2 ;;
    --ssh-peer)
      [ "$#" -ge 2 ] || fail "--ssh-peer 需要 IP 地址"
      SSH_PEER_OVERRIDE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "未知参数：$1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || fail "请使用 root 运行"
[ -d "$ROOT_DIR/.git" ] || fail "不是 v6only 项目目录：$ROOT_DIR"
[ -f "$ROOT_DIR/tools/build.py" ] || fail "项目不完整：缺少 tools/build.py"
[ -f "$ROOT_DIR/src/lib/v6only.py" ] || fail "项目不完整：缺少源码入口"
need_cmd python3
need_cmd bash
need_cmd systemctl
need_cmd dpkg-query
need_cmd apt-get

if [ ! -f /etc/os-release ]; then fail "无法识别 Linux 发行版"; fi
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *) fail "仅支持 Debian/Ubuntu，当前：${ID:-unknown}" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail "自动获取 sing-box 当前仅支持 amd64/x86_64" ;;
esac

say "检查 systemd、TUN、IPv6 和当前 SSH 管理路径"
systemctl is-system-running >/dev/null 2>&1 || [ -d /run/systemd/system ] || fail "当前系统不是可用的 systemd 环境"
[ -e /dev/net/tun ] || fail "缺少 /dev/net/tun，无法运行 sing-box TUN"
if command -v ip >/dev/null 2>&1; then
  ip -6 route show default >/dev/null 2>&1 || fail "当前没有 IPv6 默认路由"
else
  say "警告：当前缺少 iproute2/ip；正式事务会先自动安装依赖"
fi
for optional in ip nft ss; do
  command -v "$optional" >/dev/null 2>&1 || say "提示：$optional 缺失，将由正式事务安装依赖"
done

SSH_PEER="$SSH_PEER_OVERRIDE"
if [ -z "$SSH_PEER" ] && [ -n "${SSH_CONNECTION:-}" ]; then
  SSH_PEER="$(printf '%s\n' "$SSH_CONNECTION" | awk 'NR==1 {print $1}')"
fi
if [ -n "$SSH_PEER" ]; then
  python3 - "$SSH_PEER" <<'PY'
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("--ssh-peer 不是合法 IP 地址")
PY
else
  say "警告：未检测到 SSH_CONNECTION；将不自动添加管理端 CIDR"
fi
# Netcatty/跳板场景可能把 SSH_CONNECTION 显示为本机转发地址；
# 显式 --ssh-peer 时，将真实管理端传给核心安全检查。
if [ -n "$SSH_PEER_OVERRIDE" ]; then
  SSH_CONNECTION="$SSH_PEER 0 0 0"
  export SSH_CONNECTION
fi

EXISTING_INSTALLED=0
if [ -f "$STATE_DIR/runtime.json" ]; then
  if python3 - "$STATE_DIR/runtime.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        sys.exit(0 if json.load(f).get("installed") is True else 1)
except Exception:
    sys.exit(1)
PY
  then
    EXISTING_INSTALLED=1
  fi
fi

say "检查运行用户 $RUN_USER (UID $RUN_UID)"
if getent passwd "$RUN_UID" >/dev/null 2>&1; then
  EXISTING_NAME="$(getent passwd "$RUN_UID" | cut -d: -f1)"
  [ "$EXISTING_NAME" = "$RUN_USER" ] || fail "UID $RUN_UID 已被用户 $EXISTING_NAME 占用，拒绝覆盖"
elif getent passwd "$RUN_USER" >/dev/null 2>&1; then
  EXISTING_UID="$(id -u "$RUN_USER")"
  [ "$EXISTING_UID" = "$RUN_UID" ] || fail "$RUN_USER 已存在但 UID 为 $EXISTING_UID，拒绝修改"
elif [ "$DRY_RUN" -eq 0 ]; then
  useradd --uid "$RUN_UID" --create-home --home-dir "/home/$RUN_USER" --shell /usr/sbin/nologin --user-group "$RUN_USER"
  chmod 0750 "/home/$RUN_USER"
  say "已创建 $RUN_USER，UID=$RUN_UID，shell=/usr/sbin/nologin"
else
  say "计划创建 $RUN_USER，UID=$RUN_UID，shell=/usr/sbin/nologin"
fi

say "构建并校验单文件入口"
if [ "$DRY_RUN" -eq 1 ]; then
  [ -x "$ENTRY" ] || fail "dry-run 需要已有可执行入口：$ENTRY"
  say "dry-run：不重写构建产物"
else
  (cd "$ROOT_DIR" && PYTHONDONTWRITEBYTECODE=1 python3 -B tools/build.py >/dev/null)
fi
[ -x "$ENTRY" ] || fail "缺少可执行入口：$ENTRY"
sha256sum "$ENTRY"
if [ "$SKIP_TESTS" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  (cd "$ROOT_DIR" && PYTHONDONTWRITEBYTECODE=1 python3 -B tools/check.py >/tmp/v6only-oneclick-tests.log)
  tail -20 /tmp/v6only-oneclick-tests.log
else
  say "跳过项目测试（dry-run 或 --skip-tests）"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  say "dry-run 策略预览"
  if [ "$EXISTING_INSTALLED" -eq 1 ] && [ -f "$STATE_DIR/runtime.json" ]; then
    python3 - "$STATE_DIR/runtime.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    policy = json.load(f).get("policy")
if not isinstance(policy, dict):
    raise SystemExit("现有 runtime.json 缺少有效 policy")
print(json.dumps(policy, ensure_ascii=False, indent=2))
PY
    say "将复用现有已确认策略（包括管理端 CIDR）"
  else
    printf '%s\n' "将创建 UID 1500、Google DoH、google.com 健康检查和 19 条规则"
  fi
  say "dry-run 完成：未创建用户、未安装依赖、未重写构建产物、未写入状态或规则、未改网络"
  exit 0
fi

say "生成安装策略"
if [ "$EXISTING_INSTALLED" -eq 1 ] && [ -f "$STATE_DIR/runtime.json" ]; then
  python3 - "$STATE_DIR/runtime.json" "$POLICY_FILE" <<'PY'
import json, sys
source, target = sys.argv[1:]
with open(source, encoding="utf-8") as f:
    state = json.load(f)
policy = state.get("policy")
if not isinstance(policy, dict):
    raise SystemExit("现有 runtime.json 缺少有效 policy，拒绝覆盖")
with open(target, "w", encoding="utf-8") as f:
    json.dump(policy, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(json.dumps(policy, ensure_ascii=False, indent=2))
PY
  say "已复用现有已确认策略（包括管理端 CIDR），不会覆盖现有网络安全边界"
else
  python3 - "$POLICY_FILE" "$SSH_PEER" <<'PY'
import ipaddress
import json
import sys

out, peer = sys.argv[1:]
management = []
if peer:
    try:
        address = ipaddress.ip_address(peer)
        management = [str(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))]
    except ValueError:
        raise SystemExit(f"非法 SSH 对端地址：{peer}")
policy = {
    "include_uids": [1500],
    "dns_upstream": "https://dns.google/dns-query?bootstrap=2001:4860:4860::8844",
    "dns_port": 1053,
    "tun_addresses": ["172.31.255.1/30", "fdfe:dcba:9876::1/126"],
    "fake_ipv4": "198.18.0.0/15",
    "fake_ipv6": "fc00::/18",
    "route_table": 47620,
    "rule_priority": 12000,
    "management_cidrs": management,
    "health_domains": ["google.com"],
    "protect_units": ["dynamicv6-next-guest.service"],
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(policy, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(json.dumps(policy, ensure_ascii=False, indent=2))
PY
fi
printf '%s\n' "${DOMAINS[@]}" > "$DOMAINS_FILE"

say "安装计划"
printf '%s\n' "入口：$ENTRY" "状态目录：$STATE_DIR" "后端：sing-box 1.14.1" "运行用户：$RUN_USER ($RUN_UID)" "规则数：${#DOMAINS[@]}" "DoH：$DNS_UPSTREAM" "健康域名：$HEALTH_DOMAIN" "UFW：保持当前状态，不由本安装器启用"

say "导入 19 条分流规则"
V6ONLY_STATE_DIR="$STATE_DIR" V6ONLY_ENTRY="$ENTRY" "$ENTRY" import "$DOMAINS_FILE"

ACTION="install"
if [ "$EXISTING_INSTALLED" -eq 1 ]; then
  ACTION="apply"
fi

say "执行正式事务（$ACTION，sing-box 1.14.1）"
if [ "$ACTION" = "install" ]; then
  V6ONLY_STATE_DIR="$STATE_DIR" V6ONLY_ENTRY="$ENTRY" "$ENTRY" install \
    --backend singbox \
    --policy "$POLICY_FILE" \
    --entry "$ENTRY" \
    --accept-network-change \
    --accept-broad-ipv4-block \
    --confirm-timeout 300
else
  V6ONLY_STATE_DIR="$STATE_DIR" V6ONLY_ENTRY="/usr/local/sbin/v6only" /usr/local/sbin/v6only apply \
    --policy "$POLICY_FILE" \
    --accept-network-change \
    --accept-broad-ipv4-block \
    --confirm-timeout 300
fi

say "确认当前事务"
V6ONLY_STATE_DIR="$STATE_DIR" V6ONLY_ENTRY="/usr/local/sbin/v6only" /usr/local/sbin/v6only confirm || {
  say "提示：事务可能已自动提交或当前没有待确认事务；继续执行检查"
}

say "等待 TUN、DNS 和自动路由稳定"
i=0
while [ "$i" -lt 30 ]; do
  if systemctl is-active --quiet v6only-singbox.service \
     && ip link show v6only0 >/dev/null 2>&1 \
     && ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.1:1053|\[::1\]:1053'; then
    break
  fi
  i=$((i + 1))
  sleep 2
done

say "执行最终健康检查"
V6ONLY_STATE_DIR="$STATE_DIR" V6ONLY_ENTRY="/usr/local/sbin/v6only" /usr/local/sbin/v6only check
V6ONLY_STATE_DIR="$STATE_DIR" V6ONLY_ENTRY="/usr/local/sbin/v6only" /usr/local/sbin/v6only status

if [ -x "$ROOT_DIR/tools/ufw-compat.sh" ] && command -v ufw >/dev/null 2>&1; then
  say "安装/刷新 UFW 兼容检查层（不启用 UFW）"
  "$ROOT_DIR/tools/ufw-compat.sh" install
else
  say "提示：未安装 UFW 或缺少兼容脚本，跳过 UFW 兼容层"
fi

say "一键安装/修复完成"
printf '%s\n' \
  '正式入口：/usr/local/sbin/v6only' \
  '后端服务：v6only-singbox.service' \
  '运行用户：v6only-run (UID 1500)' \
  'DNS：127.0.0.1:1053、[::1]:1053，经 Google DoH IPv6 bootstrap' \
  '规则：19 条，当前不包含 openai.com 根域，仅包含 *.openai.com' \
  '安全：UFW 未由安装器启用；请单独设计并验证防火墙规则后再启用' \

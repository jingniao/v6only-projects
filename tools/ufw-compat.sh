#!/usr/bin/env bash
# v6only 与 UFW 的长期兼容层
# install: 安装检查器、systemd 检查单元并确保 SSH 端口规则存在
# check:   只读检查 UFW/v6only 是否满足兼容条件
# prepare: 仅准备 SSH 放行和检查单元，不启用 UFW
set -euo pipefail

ENTRY="/usr/local/sbin/v6only"
CHECKER="/usr/local/sbin/v6only-ufw-compat"
UNIT="/etc/systemd/system/v6only-ufw-check.service"
SSH_PORT="22222"

say() { printf '[v6only-ufw] %s\n' "$*"; }
fail() { say "错误：$*" >&2; return 1; }
need_root() { [ "$(id -u)" -eq 0 ] || fail '请使用 root 运行'; }

ufw_active() {
  ufw status 2>/dev/null | grep -q '^Status: active$'
}

check_ssh_rule() {
  ufw show added 2>/dev/null | grep -Eq "ufw allow ${SSH_PORT}/tcp( |$)"
}

check() {
  local failed=0 table
  command -v ufw >/dev/null 2>&1 || { say 'UFW 未安装'; return 0; }
  [ -x "$ENTRY" ] || { say "缺少正式入口：$ENTRY"; failed=1; }

  if ! ufw_active; then
    say 'UFW 当前未启用；兼容检查仅验证准备条件'
  else
    if check_ssh_rule; then
      say "SSH TCP/${SSH_PORT}：已放行"
    else
      say "SSH TCP/${SSH_PORT}：未在 UFW 用户规则中放行"
      failed=1
    fi

    if grep -q '^DEFAULT_OUTPUT_POLICY="ACCEPT"' /etc/default/ufw; then
      say 'UFW 出站策略：ACCEPT'
    else
      say 'UFW 出站策略不是 ACCEPT；DoH、dynamicv6 和 sing-box 可能被阻断'
      failed=1
    fi
  fi

  if systemctl is-active --quiet v6only-singbox.service; then say 'sing-box 服务：active'; else say 'sing-box 服务：非 active'; failed=1; fi
  if systemctl is-active --quiet v6only-guard.service; then say 'v6only guard：active'; else say 'v6only guard：非 active'; failed=1; fi
  if ip link show v6only0 >/dev/null 2>&1; then say 'TUN v6only0：存在'; else say 'TUN v6only0：不存在'; failed=1; fi
  if ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.1:1053|\[::1\]:1053'; then say 'DNS 1053：监听正常'; else say 'DNS 1053：未监听'; failed=1; fi

  table=$(nft list tables 2>/dev/null | awk '$1=="table" && $3 ~ /^v6only_/ {print $3; exit}')
  if [ -n "$table" ]; then say "v6only nft 表：$table"; else say 'v6only nft 表：未找到'; failed=1; fi

  if [ -x "$ENTRY" ]; then
    if "$ENTRY" check 2>/dev/null | grep -q '"ok": true'; then say 'v6only health：ok=true'; else say 'v6only health：失败'; failed=1; fi
  fi

  if [ "$failed" -eq 0 ]; then
    say '兼容检查通过'
    return 0
  fi
  say '兼容检查未通过；不要直接启用 UFW'
  return 1
}

install_compat() {
  need_root
  command -v ufw >/dev/null 2>&1 || fail '未安装 ufw'
  command -v systemctl >/dev/null 2>&1 || fail '缺少 systemctl'
  command -v ip >/dev/null 2>&1 || fail '缺少 iproute2'
  command -v nft >/dev/null 2>&1 || fail '缺少 nftables'
  command -v ss >/dev/null 2>&1 || fail '缺少 iproute2/ss'
  [ -x "$ENTRY" ] || fail "缺少正式入口：$ENTRY"

  if ! check_ssh_rule; then
    say "添加 SSH TCP/${SSH_PORT} UFW 放行规则（不启用 UFW）"
    ufw allow "${SSH_PORT}/tcp" >/dev/null
  else
    say "SSH TCP/${SSH_PORT} UFW 规则已存在"
  fi

  install -m 0755 "$0" "$CHECKER"
  cat > "$UNIT" <<'EOF'
[Unit]
Description=v6only UFW compatibility check
Wants=network-online.target v6only-guard.service v6only-singbox.service
After=network-online.target ufw.service v6only-guard.service v6only-singbox.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/v6only-ufw-compat check
User=root
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable v6only-ufw-check.service >/dev/null
  say '兼容检查服务已安装并启用（不会自动启用 UFW）'
  check
}

case "${1:-check}" in
  check) check ;;
  install|prepare) install_compat ;;
  *) say '用法：v6only-ufw-compat {check|install|prepare}'; exit 2 ;;
esac

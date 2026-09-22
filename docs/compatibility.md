# 兼容性与技术限制

## 已验证版本

- 管理器：0.3.1-dev，Linux、Bash、Python 3.9+；实际测试为 Python 3.13.5。
- sing-box：固定 1.14.1 正式版，运行 TUN 使用 gVisor，官方发布时间 2026-09-15T00:06:50Z。已核对官方 GitHub 元数据及归档 SHA-256，执行官方 check 和隔离真实网络测试。
- dnsmasq：固定 2.91，测试包为 Debian 2.91-1+deb13u2 amd64。官方 --test 和真实 DNS 分派测试通过。
- 实际开发内核为 Linux 6.12.107+deb13-amd64；结果中的环境以本机 `.dev-state/test-results.md` 为准。

实际部署入口的实验平台门槛为 Debian 12/13、Ubuntu 22.04/24.04 + systemd。这是明确拒绝其他系统的边界，**不是四个发行版全部完成安装验收的声明**。当前自动 sing-box 下载只覆盖 amd64；其他架构需单独提供并验证二进制。dnsmasq 自动安装只接受仓库中的 2.91，不为迁就发行版而静默改用其他版本。

入口需要已有 Python；缺少时退出 3。安装器可检测和安装 iproute2、nftables、ca-certificates，以及匹配版本的 dnsmasq-base。开发下载工具只提取到项目缓存，没有安装系统包。

## 官方依据

曾按固定版本保存上游官方文档、关键源码快照与来源摘要清单（`docs/reference/` 已不随仓库分发）；[sing-box 下载锁](../tools/singbox-release.json)、[dnsmasq 下载锁](../tools/dnsmasq-release.json)仍记录下载来源和摘要。

sing-box 该发布资产列表未发现独立签名，本轮只核对 GitHub 官方发布摘要，没有声称完成签名验证。dnsmasq 测试包摘要来自本机已有 Debian APT 索引并与官方下载核对；未重新验证整套仓库签名链。

1.14.1 已移除旧 outbound domain_strategy，当前使用 domain_resolver 和 resolve。DNS 路由动作 strategy 有后续弃用计划，不能外推到其他版本；更新只使用本管理器锁定并验证的版本。

## 运行限制

- 只选择明确的本地 UID，1–16 个，不自动覆盖 root、容器或其他命名空间。
- 健康域名 1–3 个；检查有期限，不使用真实 API 密钥，不判定账号/地区权限。
- 端口、TUN/FakeIP 地址范围、路由表和优先级冲突会拒绝。优先于项目的已有策略需要单独适配。
- 路由标识和虚拟地址范围在同一实例内保持不变；变更需先完成卸载和清理。动态公网 IPv6 不在这些固定字段中。
- DNS 接管针对本机 TCP/UDP 53；D-Bus 系统解析代理、DoH、ECH 与应用缓存存在边界。
- 含扩展属性/ACL 的被管理文件拒绝自动覆盖，需先做单独兼容性处理。
- 不为 cached IPv4 自动改拨 IPv6；可见域名命中时拒绝，无法识别时按普通流量。
- 发行版全集、真实 PID 1/日志轮转、真实 DynamicV6、目标 SSH、重启和极端断电恢复尚未验收。

IDNA 采用 Python 标准库 IDNA 2003 往返校验；部分 IDNA 2008 名称会保守拒绝。详见 domain-rules.md。

隔离故障恢复测试中，system 栈在 IPv6 路由/地址恢复后出现过间歇性后续连接超时，因此最终选择 gVisor。两种栈在连接被后端关闭时可表现为重置或 EOF；测试以有效应用载荷/服务端连接家族验证成功，不能把空读取当作业务连接成功。最终选择的测试结果见本机 `.dev-state/test-results.md`。

## 本轮修复与现场限制（0.3.1-dev）

以下为本轮修复与在 独立 VPS / Debian 13 / 内核 6.12 实机复测得到的结论。

### 已修复

- **B1 资源归属误判（严重）**：后端服务重启后，sing-box 的 auto_route 规则/路由（优先级 12016+、专属路由表）会被误判为外部修改，导致 apply/reinstall/uninstall/rollback 全部失败并卡在 `restore_failed`。现改为按归属特征识别：专属路由表，或优先级保留区间内且 UID 属于接管清单的规则；不再要求「实时 ⊆ 静态快照」。`cleanup_kernel` 在快照缺失时按实际采集资源清理，不再直接拒绝。
- **B3 恢复出口**：`restore_failed` 允许 `rollback --accept-network-change` 重新恢复；`check` 在该状态下输出只读诊断（含实时/期望内核资源），不再直接拒绝。
- **B2 保护单元探测**：默认 `protect_units` 探测本机实际存在的 `*dynamicv6*` 单元，而非写死 `DynamicV6.service`。
- **B4 前置检查**：`doctor` 输出本机现有非系统 UID（`available_uids`）；无可用 UID 时给出建用户示例。

- **B7 中断事务出口**：事务被中断（`prepared`/`rollback_armed`/`applying`/`restoring`）后，`check` 与 `status` 给出只读诊断与恢复指引，`rollback --accept-network-change` 可收尾，不再永久卡死。
- **B8 运行时状态测试隔离**：`Host` 支持 `V6ONLY_ROOT` 覆盖运行时根目录，单元测试不再读取真实 /var/lib/v6only，避免被宿主机残留状态干扰。

### 现场限制

- **DNS 上游必须为 IPv4**：本机 IPv6 DNS 上游（如 2001:4860:4860::8888、2606:4700:4700::1111）不可达（connection refused），`dns_upstream` 需使用 IPv4（如 8.8.8.8）。
- **FakeIP 全局生效**：命中与未命中域名在 DNS 层都返回 FakeIP，无法据 DNS 结果判断是否命中。改用 `v6only test <域名> --explain` 在本地清单层输出命中判定（不联网、不写日志）。
- **重启验收未执行**：目标机重启相关性验收仍未进行，属高风险操作，需单独授权。

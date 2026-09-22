# 开发记录

## 0.3.1-dev

修复 B1（后端重启后资源归属误判导致 restore_failed 卡死）、B2（protect_units 探测实际 DynamicV6 单元）、B3（restore_failed 可经 rollback 恢复；check 提供只读诊断）、B4（doctor 输出可用非系统 UID 与建用户示例）。新增 `test --explain` 本地命中判定，以及归属判定与恢复路径的回归测试（80 项全部通过）。另修复中断事务的只读诊断与恢复出口（B7）及运行时状态的测试隔离（B8，新增 V6ONLY_ROOT）。现场限制见 docs/compatibility.md。

修复内核快照捕获竞态：此前 runtime 在 `wait_ready()`（仅判定 systemd 单元 active + DNS 端口可连）之后立即抓取 `kernel_snapshot`，而 sing-box `auto_route` 的 ip 规则/路由要稍后才写入 TUN 窗口，短快照使后续 `uninstall`/`disable`/`apply` 误判「残留内核资源包含用户后续修改」并以退出码 5 失败，且无内置修复路径。现新增 `LiveHost.wait_settled()`（在窗口静默后才抓取），并让 `cleanup_kernel()` 复用 `kernel_conflicts()` 既有的归属判定（真正的项目外资源仍以退出码 5 拒绝）。回归测试增至 87 项全部通过；真实宿主复现与修复验证见本机开发记录（不随仓库分发）。

修复 BUG-15-01（阻塞级）：回滚恢复路径 `_restore` 仍沿用旧的采样时序——`wait_ready()` 之后立即采集 `kernel_snapshot`，把 `auto_route` 尚未落地的窗口写成残缺快照（真机实测记录 rules 3 / routes 0，而实机为 rules 29 / routes 33）。此后 `check` / `apply` 一律以退出码 5 报「归属资源发生外部变化」并死锁，只能人工修正 `runtime.json`。现与 apply 路径对齐，改为 `wait_ready` → `wait_settled` → 采集快照（仅 sing-box 后端，仍在原超时保护内）。新增回归用例「回滚必须先等窗口稳定再采集快照」「回滚后 `check` 必须通过」，单元测试增至 89 项全部通过；`tools/check.py` 全套（B01/U01/U02/S01/S03/D01/C01/I01/I02）通过。同时修复 `tools/check.py` 的 D01 假失败：链接扫描把行内代码中的域名正则（`…](?:[a-z0-9-]{0,61}…`）误判为失效本地链接，现扫描前屏蔽围栏代码块与行内代码。本机修复记录见开发环境（不随仓库分发）；真机复验（新产物部署、未确认超时自动恢复、手动 rollback、SIGKILL 级后端死亡与自动恢复、真实 SERVFAIL 不回退 IPv4、客户端 DoH）见开发环境第 17 轮记录，该轮 `check` 在恢复后为 exit 0、快照 29 / 33 完整。

完成目标机第 18 轮验收（真机 live）。**实际 APT 安装窗口**：真机依赖已齐备，工具不会自发进入窗口，故先 `apt-get remove -y dnsmasq-base`（叶子包，模拟仅删其自身）再以 `v6only backend use dnsmasq` 触发重装；实测窗口 3.29 s（`/usr/sbin/policy-rc.d` 08:42:33.319Z 出现 mode 755 → 08:42:36.608Z 恢复为不存在），窗口内 `invoke-rc.d --query` 被拒（exit 101，`policy-rc.d denied execution of start.`），全部 `apt`/`dpkg` 运行采样均落在窗口内、窗口外零次（372 次采样），`apt`/`dpkg` 日志时间戳亦在窗口内；`dbus.service` 与 `ssh.service` 窗口后 `NRestarts=0`，三者 `ActiveEnterTimestamp` 仍为开机时刻，证明自启策略确实阻止了启动/重启；共享依赖记录 before `config-files` → after `installed`、`retained: true`（新装依赖保留）。**整机冷启动**（用户授权后由其本人执行重启，代理侧重启命令被安全策略拦截且未绕过任何路径）：`boot_id` 更换、项目专属 journal 命名空间出现第 2 个 boot；`v6only-guard.service`（oneshot，`After=network-online.target`）与 `v6only-singbox.service` 均 enabled 自动拉起（开机 18 s 内，`NRestarts=0`、`ExecMainStatus=0`）；nft 表 / `ip rule` / `table 47620` 路由 / TUN / 监听端口与重启前逐行一致（内核态由 guard 与 sing-box 冷启动重建），关键文件哈希仅 `singbox-cache.db` 因缓存落盘而变化；FakeIP 映射（openai `fc00::3`、google `fc00::2`、jd `fc00::6`）经缓存库二进制核对确认由 `singbox-cache.db` 恢复而非重新分配；uid1500 业务、`check`（exit 0）与 `doctor` 恢复如初，保护单元 `dynamicv6-next-guest.service`（`ip rule 25423` / `table 47423`）全程未受影响。新增观察项 OBS-18-01：冷启动存在约 14 s「fail-closed 规则尚未安装」窗口（系统内无早于 guard 的持久化规则加载路径，`nftables.service` 为 disabled；本机 boot 时无 uid1500 常驻进程，窗口内无流量来源）。详见第 18 轮开发记录（不随仓库分发）。

仓库发布形态调整：不再随附逐轮测试记录（`tests/results/`、`docs/test-results-round*.md`、生成的 `docs/test-results.md`）和上游官方文档快照（`docs/reference/`）；本机自检输出改写入 `.dev-state/`，复现方式 `python3 -B tools/check.py`。

## 0.3.0-dev

实现统一生命周期事务、资源归属、独立 systemd 回滚定义、确认/恢复、升级重装、卸载清理及 APT 自启控制。新增 sing-box TUN/FakeIP/gVisor 运行配置、UID 和接口范围、独立 IPv4 故障保护，以及 dnsmasq 2.91 三实例备用后端。

新增私有审计/健康记录、专属 journal 配置、日志期限/容量、快照保留、完整中文菜单与运维文档。发行文件从自身读取并校验静态载荷，避免大型 Bash heredoc 在 dry-run 时创建临时文件。

测试扩展至模拟宿主机生命周期与依赖故障、真实回环 DNS、独立网络命名空间的 TCP/TLS/UDP 和故障恢复。目标机器实际 systemd、APT、SSH/DynamicV6 与重启仍待验收，当前为实验开发版。

## 0.2.0-dev

固定 sing-box 1.14.1，保存官方配置文档和关键源码，提供无入口候选生成、版本探测、官方静态校验与下载摘要。

## 0.1.0-dev

首次交付中文管理入口、域名清单、无副作用规则预览、原子存储、基本历史、单文件构建与单元测试。

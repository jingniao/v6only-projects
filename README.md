# v6only

中文 Linux 域名网络管理工具，当前为 **0.3.1-dev 实验开发版**。已实现清单管理、候选配置、sing-box TUN、dnsmasq 备用模式、事务恢复、生命周期命令及日志。代码、模拟宿主机测试和真实隔离网络测试分别记录，**尚未完成目标服务器的真实安装、SSH/DynamicV6 和重启验收**。

## 安全开始

运行前需要 Linux、Bash、Python 3.9+。不需要第三方 Python 包，不宣称零依赖。普通清单操作不需要 root：

```bash
cd /root/projects/v6only
export V6ONLY_STATE_DIR="$PWD/.dev-state"
./dist/v6only help
./dist/v6only add 'openai.com' '*.openai.com'
./dist/v6only import examples/domains.txt.example
./dist/v6only list
./dist/v6only apply --dry-run
./dist/v6only history
```

无参数在终端展示完整中文菜单；非交互环境输出帮助并退出。`add/remove/import` 只改变待应用清单，`import` 合并去重，`export` 拒绝覆盖已有文件。通配符在 shell 中要加引号。

## 当前能力与验证层级

| 能力 | 实现与验证 |
| --- | --- |
| 中文菜单、命令行、输入验证、精确/仅子域规则 | 源码与单文件入口单元测试 |
| 清单增删查、导入导出、并发锁、原子提交 | 临时目录实际文件测试 |
| sing-box 1.14.1 候选与运行配置 | 官方 check；隔离 TUN 测试 |
| IPv6-only TCP/TLS/UDP、无 AAAA/IPv6 故障不回退 | 独立网络命名空间与合成服务端实测 |
| dnsmasq 2.91 精确/通配、CNAME、HTTPS/SVCB | 官方 --test；真实回环 DNS 实测 |
| install/apply/confirm/backend/update/reinstall | 事务代码完成；生命周期在模拟宿主机测试 |
| disable/enable/rollback/uninstall/purge | 文件、恢复、冲突、清理顺序等模拟测试 |
| 独立 systemd 回滚、后台服务、持久 journal | 定义已实现、静态验证；真实 PID 1 运行未验收 |
| APT 依赖安装、自启控制、包状态记录 | 代码与故障模拟测试；未在宿主机安装包 |
| 日志脱敏、保留期、容量与历史 | 本地文件测试；真实 journal 轮转未验收 |

完整且最新的数量、命令、环境和实际输出由本机 `python3 -B tools/check.py` 生成到 `.dev-state/`（逐轮记录不随仓库分发）。

## 两种网络保障

主后端只接管默认网络命名空间中明确选定的 UID。本地普通 DNS 查询按 UID 转到专属前端，FakeIP 把目标保留为域名；命中清单的解析和出站均限定 IPv6。未命中的已识别域名优先 IPv6、允许 IPv4 回退。root、管理路径和其他命名空间不默认纳入。

主后端故障时，独立 nftables 规则会阻断选定 UID 更广泛的非管理 IPv4 流量，以避免静默恢复直连。需要明确接受这个影响范围。直接 IP、缓存 IP、DoH、ECH、既有连接和无法识别域名的场景有边界，见 [网络设计](docs/network-design.md)。

备用后端仅为 **DNS 约束模式**。它能按域名分派过滤，但不能阻止缓存 IPv4、独立 DNS 或直接 IP。切换必须明确确认保障降低。

## 预览与候选校验

```bash
# 示例上游是文档地址，不可直接用于部署；生成时不会查询它。
./dist/v6only config render --backend singbox --dns-server 192.0.2.53 --dry-run
./dist/v6only config render --backend dnsmasq --dns-server 192.0.2.53 --dry-run

# 查看完整 TUN/nftables 计划，不改文件、不运行外部校验器。
./dist/v6only install --backend singbox --policy examples/policy.json.example --dry-run
```

`config render` 的 sing-box 候选刻意没有入口，适合单独检查；实际运行配置由生命周期管理器生成。`install --dry-run` 在提供完整策略时会输出实际运行配置和 nftables 计划。所有预览均不安装软件、不改网络、不写审计。

本地校验器需要显式提供；开发工具只下载提取到项目缓存：

```bash
python3 -B tools/fetch_singbox.py --dry-run
python3 -B tools/fetch_dnsmasq.py --dry-run
# 明确决定下载后，再执行不带 --dry-run 的相应命令。
./dist/v6only backend probe singbox --binary "$PWD/.cache/sing-box-1.14.1/sing-box"
./dist/v6only config validate templates/singbox-candidate.example.json --binary "$PWD/.cache/sing-box-1.14.1/sing-box"
```

固定版本、来源、摘要和签名限制见 [兼容性说明](docs/compatibility.md)。

## 生命周期使用

实际安装/接管需要 root、支持的 systemd 系统、完整策略以及显式授权参数。先按 [部署与运维手册](docs/operations.md) 勘察目标机器，替换示例中的 UID、DNS 和健康域名。不能把文档中的示例地址直接投入运行。

生命周期变更先临时生效，再由 `confirm` 提交；默认 180 秒未确认则由项目专属任务恢复。`uninstall` 先验证网络恢复再移除组件，保留清单、历史、必要快照及入口；`purge` 只有在已确认卸载后才清理项目数据。未知文件或外部修改会阻止恢复/清理。

## 构建与测试

```bash
python3 -B tools/build.py
python3 -B tools/check.py
# 缓存准备好且允许创建独立网络命名空间时：
python3 -B tools/check.py --integration
```

发行目标是 `dist/v6only` 单文件 Bash 入口，内嵌受版本管理的 Python 模块。Python 从发行文件读取并核对静态载荷，不占用交互 stdin，也不依赖 Bash 临时 heredoc 文件。构建无下载、无时间戳，同一源码结果一致。禁止修改发行文件后绕过构建。

## 数据位置

开发清单目录优先级：`--state-dir` → `V6ONLY_STATE_DIR` → `$XDG_STATE_HOME/v6only` → `~/.local/state/v6only`。安装后的 `/usr/local/sbin/v6only` 默认使用 `/var/lib/v6only`。首次安装会保留所用清单及其历史到系统项目目录。

运行配置在 `/etc/v6only`，后端在 `/opt/v6only`，事务/快照/缓存在 `/var/lib/v6only`，审计/健康记录在 `/var/log/v6only`，服务日志使用专属 journal 命名空间。目录及敏感数据默认私有。源码和单文件入口保留管理接口，卸载不默认删除入口或共享依赖。

## 文档导航

- [原始规范](PROJECT_SPEC.md)、[需求追踪](docs/requirements.md)、[开发与验收清单](docs/development-checklist.md)
- [架构](docs/architecture.md)、[网络设计](docs/network-design.md)、[CLI](docs/cli-design.md)
- [域名规则](docs/domain-rules.md)、[sing-box 配置依据](docs/singbox-candidates.md)、[dnsmasq 设计](docs/dnsmasq.md)
- [安全与恢复](docs/safety-and-rollback.md)、[日志](docs/logging.md)、[运维与排障](docs/operations.md)
- [兼容性与限制](docs/compatibility.md)、[验收方案](docs/acceptance-tests.md)

逐轮测试记录与上游官方文档快照不随仓库分发；本机复现：`python3 -B tools/check.py`（可选 `--integration`），输出写入 `.dev-state/`。

开发与隔离测试不等于目标服务器部署授权。本轮没有修改宿主机 DNS、路由、防火墙、RA、cloud-init 或 DynamicV6，没有创建宿主机服务或重启服务器。

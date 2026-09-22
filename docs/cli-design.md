# CLI 与中文菜单

通用选项为 --state-dir、--dry-run、-h/--help。终端无参数展示 25 项中文菜单，非交互环境显示帮助后退出。每次菜单操作完成后退出，可再次运行。

| 命令 | 行为 |
| --- | --- |
| help / version | 中文帮助与 0.3.1-dev 版本 |
| add 规则... / remove 规则... | 只改待应用清单，重复操作幂等 |
| list / import 文件 / export 新文件 | 查看、合并导入、拒绝覆盖的导出 |
| config render --backend singbox或dnsmasq --dns-server IP | 生成独立候选，--output 写新文件 |
| config validate 文件 --binary 路径 | 复核候选后调用固定版本官方校验器 |
| backend probe 后端 --binary 路径 | 只核对后端版本，不运行服务 |
| install --backend 后端 | 检查环境、获取组件、安排恢复、临时安装接管 |
| apply | 应用待应用清单，等待确认 |
| confirm [--transaction ID] | 只提交当前未超时事务并取消其任务 |
| backend use 后端 | 使用当前已应用清单进行事务化切换 |
| status | 显示已提交及临时生效状态，避免把待确认接管显示为未运行 |
| check | 本地校验；已安装时检查归属、服务、选路与 DNS/TLS |
| test 域名 | 有总期限的 DNS 与 IPv6 TCP/TLS 检查，记录健康报告 |
| doctor | 平台、依赖、TUN、systemd 等只读环境报告 |
| logs [audit或changes或health或service] | 本地记录或专属 journal |
| history | 清单历史与已提交运行变更 |
| update | 升级到本管理器锁定的已测试稳定版；已是该版本则不重启 |
| reinstall | 重新获取并校验组件，以事务方式重装 |
| disable / enable | 明确解除限制 / 重新启用已应用清单 |
| rollback [--transaction ID] | 恢复当前事务；拒绝撤销被较新事务覆盖的旧状态 |
| uninstall | 恢复并验证网络后移除运行组件，保留数据和入口 |
| purge [--keep-logs] [--remove-entry] --yes | 确认卸载后清理归属资源；依赖默认保留 |

实际安装、应用、切换、升级、停用、启用、回滚和卸载需要 --accept-network-change。启用 sing-box 还要 --accept-broad-ipv4-block；启用 dnsmasq 要 --accept-dns-downgrade。菜单在展示计划后收集相同确认。

策略可用 --policy 指定完整 JSON，或首次通过 --include-uid（可重复）、--dns-server、--health-domain（可重复）、--management-cidr 配置。两种方式不能混用。逐项模式会纳入当前 SSH 对端；策略文件需自行包含其 /32 或 /128 排除地址。

--binary 指定可信后端文件；--entry 指定新管理入口。首次安装建议使用已经构建的 dist/v6only 作为 --entry。--confirm-timeout 为 30–3600 秒，默认 180 秒。所有生命周期临时变更均须 confirm；超时恢复。低期限可能不足以完成网络健康检查。

所有写操作有 --dry-run。预览不安装、不写锁/配置/审计、不联网、不运行外部校验器。提供完整策略时，install/apply 的预览包含真实运行配置和 nftables 文本；尚未执行环境勘察的事实会明确显示。

内部 _recover、_guard、_netcheck 供服务和隔离诊断使用，不应手工拼装任意参数。_recover 不依赖 SSH_CONNECTION，使用事务保存的管理对端。

退出码：0 成功或明确的计划/待确认结果；1 文件或运行异常；2 参数错误；3 前置条件不满足；4 校验/健康失败；5 恢复、冲突或清理失败，需要保留资料处理。不会把空实现当作成功。

# 日志、审计与历史

## 本地与生产记录

待应用 state.json 保存最近 200 次实际清单变更，包含 UTC、UID、固定操作名、修订号和域名差异。它不是网络恢复快照。没有变化、只读操作和 dry-run 不产生清单事件。

运行 audit/changes/health 保存于 /var/log/v6only，以日期分文件。审计记录事务准备、待确认、提交、恢复与失败类别；变更记录当前后端和已应用规则；健康记录区分服务、选路与 DNS/TLS。test 的开发模式报告保存于开发数据目录的 logs 子目录。

目录 0700、文件 0600。凭据键、Cookie、Authorization、密钥样式和带凭据可能性的 URL 被脱敏，不存完整命令行或请求正文。详细连接域名日志默认关闭；sing-box 使用 warn，dnsmasq 不启用 log-queries。

## 保留期与容量

审计/变更建议 30 天，健康 90 天，本地运行记录合计上限 100 MiB；写入锁覆盖追加和裁剪，防止并发轮转丢失完整 JSON 行。未知文件不参与日志清理。

服务日志使用 LogNamespace=v6only。专属 journald 配置 Storage=persistent、SystemMaxUse=100M、MaxRetentionSec=30day；专属服务覆盖 LogsDirectoryMode=0700 和 UMask=0077。其轮转由 journal 协议处理，不让后端持有被重命名的普通日志文件句柄。真实 namespace 权限与轮转尚需目标验收。

本地日志与服务日志预算合计约 200 MiB；快照另按数量管理。备份默认保留最近 5 个已完成事务，同时保护当前、前一恢复基线与未解决事务，不删除唯一恢复快照。

## 查看

```bash
v6only logs audit
v6only logs changes
v6only logs health
v6only logs service --limit 100
v6only history
```

uninstall 保留记录，purge 默认清理项目日志及专属 journal。--keep-logs 保留全部项目日志与 retained-resources.json 归属凭证。不会 vacuum 或删除全系统日志。

完整命令进入事务之前被拒绝的参数/前置条件错误不一定写入生产审计；已进入事务的变更和恢复有持久记录。本版未提供周期体检 timer，不宣称持续检测网络健康。

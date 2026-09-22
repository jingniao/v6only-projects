# 使用、部署准备与排障

## 本地管理

```bash
export V6ONLY_STATE_DIR="$PWD/.dev-state"
./dist/v6only add 'openai.com' '*.openai.com'
./dist/v6only remove 'openai.com'
./dist/v6only import examples/domains.txt.example
./dist/v6only export /tmp/v6only-domains-new.txt
./dist/v6only apply --dry-run
```

导出目标必须不存在。清单内无 AAAA 的站点不会自动被移除，也不会为了连通而降级 IPv4。示例域名不保证完整覆盖或支持 IPv6。

## 目标机器准备

当前没有完成目标部署验收。实际运行前需要已有 Bash/Python 3.9+、root、systemd、TUN、可用 IPv6、可信的软件来源和明确的管理路径。建议选择专门运行目标应用的普通用户，不把 root、SSH/DynamicV6 管理用户纳入。

复制 examples/policy.json.example 并替换 UID、DNS、健康域名；192.0.2.53 是文档地址。远程操作时填写当前 SSH 对端的 /32 或 /128。doctor 可查看环境；install --dry-run 可查看完整候选和网络计划。

以下是目标验收时的命令形式，**不是本轮已经执行的部署记录**：

```bash
v6only install --backend singbox --policy /path/to/my-policy.json --entry /path/to/dist/v6only --dry-run
# 在目标部署已经明确授权、审阅计划后：
v6only install --backend singbox --policy /path/to/my-policy.json --entry /path/to/dist/v6only --accept-network-change --accept-broad-ipv4-block
v6only status
v6only confirm --transaction 当前输出的事务ID
```

默认 180 秒未确认会恢复。首次安装会保存清单到 /var/lib/v6only，安装后入口默认读取该目录。使用自定义 --state-dir 时需要一直明确选择同一数据源。

## 修改与后端切换

```bash
v6only add '*.claude.ai'
v6only apply --dry-run
v6only apply --accept-network-change --accept-broad-ipv4-block
v6only confirm

v6only backend use dnsmasq --dry-run
v6only backend use dnsmasq --accept-network-change --accept-dns-downgrade
v6only confirm
```

备用模式不能阻止缓存/独立 DNS/直接 IP。切换后应用可能仍持有旧 FakeIP，需要刷新其缓存或重启应用，工具不清除全系统 DNS 缓存来掩盖限制。

## 升级与重装

update 只切到当前管理器锁定且已验证的稳定版；已是该版本则报告无变更。--binary 可以指定可信的同版本组件用于重新验证；更新管理入口用 --entry 指向新构建的单文件。候选验证失败不切换，健康失败恢复旧二进制、配置及入口。

```bash
v6only update --dry-run
v6only reinstall --accept-network-change --accept-broad-ipv4-block
v6only confirm
```

任意不同 sing-box/dnsmasq 版本不会因为“看起来接近”而被接受。后续版本需先更新兼容性验证和下载锁。

## 停用、恢复与清理

```bash
v6only disable --accept-network-change
v6only confirm
v6only enable --accept-network-change --accept-broad-ipv4-block
v6only confirm
v6only rollback --accept-network-change

v6only uninstall --dry-run
v6only uninstall --accept-network-change
v6only confirm
v6only purge --dry-run
v6only purge --yes --keep-logs
```

disable 主动解除接管和严格限制。uninstall 先恢复网络再移除组件；默认保留清单、日志、快照、入口与共享依赖。purge 默认清理项目日志，--keep-logs 保留，--remove-entry 可同时删除未改动的入口。保留日志后可再次 purge 清理剩余日志。

## 故障处理

| 现象 | 处理 |
| --- | --- |
| 参数错误/非法域名 | 查看 help，输入完整 ASCII/punycode 域名，不输入 URL/IP/端口 |
| UID、端口、地址或规则冲突 | 用独立应用 UID 和不冲突的初始策略；不要清空系统路由来强行通过 |
| 等待确认 | 查看 status 的实际临时状态，在期限内确认当前 ID 或让其恢复 |
| 恢复失败（5） | 保留事务目录和定时器；检查 logs/history/快照，核实外部修改后再恢复 |
| 健康检查失败 | 分别检查 DNS、IPv6 路由和 TLS；401/403 不直接算网络故障 |
| 后端崩溃后 IPv4 不通 | 这是已确认的故障保护范围；修复后端，或主动 disable 解除 |
| 同名文件/未知日志阻止清理 | 先核实文件归属，不强制 rm 整个目录 |
| 无 Python/工具/支持版本 | 满足运行前置条件；不要把未支持版本伪装为已验证版本 |

不要把 /root/net-snapshots 中的旧实验备份恢复到当前机器，不修改 DynamicV6、RA、cloud-init 或当前公网地址来“修复”本项目。记录中的旧地址仅为历史，不是部署输入。

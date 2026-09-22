# 验收与证据层级

## 可复现命令

```bash
python3 -B tools/build.py
python3 -B tools/check.py
python3 -B tools/check.py --integration
```

基础检查包含双入口单元、Bash/Python 语法、构建一致性、文档链接、可用时的官方后端静态校验和 systemd unit/timer 静态校验。--integration 额外运行真实 dnsmasq 回环及真实 sing-box 独立网络命名空间测试。

测试不会安装系统包或启动宿主机服务。网络命名空间测试先比较 namespace inode，若无法隔离则失败而不在默认网络中替代执行；进程组退出时清理后端/服务端。证书和网络服务使用合成夹具，不使用真实密钥。

## 主要验收映射

| 要求 | 本轮证据 |
| --- | --- |
| 根域/仅子域与相似域名 | 单元 + dnsmasq + TUN 数据路径 |
| 非法输入不执行 | shell 注入标记、URL、IP、控制字符、长度测试 |
| dry-run 无写入 | 文件树快照 + 禁止普通文件写入的进程限制 |
| 候选无效不破坏当前配置 | 结构防篡改、官方拒绝、事务故障注入 |
| 命中有 AAAA 用 IPv6 | 实际服务端按连接家族计数，TCP/TLS/UDP |
| 命中只有 A/IPv6 故障 | 连接失败且 IPv4 服务端计数不增加 |
| 未命中允许 IPv4 | 仅 A 普通域名与直接 IP 测试 |
| 后端崩溃 | SIGKILL 后选定 UID IPv4 被阻断，root 路径可用 |
| DNS 故障 | SERVFAIL 不回退；dnsmasq filtered 停止不转 normal |
| 动态地址/规则共存 | 私有命名空间中多轮 25423/47423 风格规则和地址变更 |
| 缓存和命名空间边界 | FakeIP 正常重启、可见 SNI 缓存 IPv4、相同 UID 的其他 namespace |
| 升级/切换失败 | 模拟宿主机恢复原后端、二进制和管理入口 |
| 独立恢复/确认 | 状态机和唯一任务测试；真实 PID 1 仍待验收 |
| 卸载/清理 | 先恢复再移除、未知文件保护、保留日志后二次清理 |
| 持久日志 | 本地文件、脱敏、并发、期限和容量测试；真实 journal 待验收 |
| 重启、SSH、实际 DynamicV6 | 未执行目标服务器验收 |

隔离规则更新是受控模拟，不是运行真实 DynamicV6。systemd 静态验证使用私有测试根目录、依赖与可执行路径占位对象，没有启动服务。

每次保存测试编号、版本、UTC 时间、环境、命令、预期、完整输出、结论和限制。见本机 `python3 -B tools/check.py` 生成的 `.dev-state/test-results.md` 与 `.dev-state/results/`。逐轮记录不随仓库分发。

DNS、TCP/TLS、业务权限分开判定；HTTP 401/403 不直接等于网络故障，IPv6 可达不保证账号或地区可用。未执行项目必须写“未执行”，不得使用模拟通过结果冒充生产验收。

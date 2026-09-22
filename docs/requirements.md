# 需求追踪与交付范围

完整约束以原始 PROJECT_SPEC.md 为准，副本保持字节一致。0.3.1-dev 已从第一轮骨架推进为可测试的实验实现；下表区分代码交付和部署验收。

| 规范要求 | 实现位置 | 验证情况 |
| --- | --- | --- |
| 中文菜单、命令行和退出码 | src/lib/v6only.py | 双入口单元与伪终端测试 |
| 域名增删查、导入导出、精确与仅子域通配 | 同上 | 规范化、长度、IDNA、误匹配、并发及原子性测试 |
| sing-box TUN IPv6-only | src/backends/singbox.py、src/lib/host.py | 官方构造校验及真实隔离网络测试 |
| dnsmasq 备用及语义保真 | src/backends/dnsmasq.py | 2.91 三实例真实 DNS 测试 |
| 后端切换与降级确认 | src/lib/runtime.py | 生命周期模拟与失败恢复测试 |
| 配置校验、临时应用、确认、回滚 | runtime.py、transactions.py | 文件事务、超时、重入、冲突测试 |
| 软件获取与必要工具安装 | runtime.py、tools/fetch_*.py | 固定摘要获取实测；APT 自启控制模拟测试 |
| 持久审计、健康、日志容量 | observability.py、专属 journal 配置 | 文件日志测试；journal 运行验收待执行 |
| 升级、重装、停用、启用 | runtime.py | 模拟宿主机测试，失败保留恢复资料 |
| 卸载、清理、保留数据 | runtime.py | 恢复先于移除、未知文件保护、保留日志等测试 |
| SSH、DynamicV6、动态地址 | host.py、隔离网络测试 | root 管理路径、策略更新、地址变化实测；真实服务未验收 |
| 重启与目标服务器生命周期 | 已提供流程和验收记录模板 | 未执行，需要目标部署授权 |

运行入口需要已有 Bash 和 Python 3.9+；安装器可以补齐 iproute2、nftables、CA 证书，以及支持版本的 dnsmasq-base。没有 Python 时会明确拒绝，不声称零依赖或已经自动安装了解释器。

选定 UID 的普通 DNS 由项目 nftables OUTPUT 规则分派，不改写系统 DNS 文件。TUN 规则限定本机输出接口和用户范围，不自动接管容器。故障保护的更广泛 IPv4 阻断需要确认。备用模式的保障降低必须确认。

直接 IP、DoH/ECH、应用缓存、既有连接等不是无条件防绕过承诺。不能封禁共享 CDN 全部 IPv4 冒充域名控制，也不能以静态配置通过代替网络验收。

本轮授权内的交付包括源码、完整中文文档、可复现单文件产物、单元/模拟测试、官方校验和隔离网络测试。没有执行宿主机部署、实际 APT 安装、systemd 接管或重启。

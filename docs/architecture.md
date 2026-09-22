# 架构

## 模块

| 模块 | 职责 |
| --- | --- |
| src/v6only.sh | 源码入口、Python 前置检查、保留用户 stdin |
| src/lib/v6only.py | 中文界面、域名解析、待应用清单、命令编排 |
| src/backends/singbox.py | 固定版本候选、TUN/FakeIP 配置和官方校验 |
| src/backends/dnsmasq.py | 三实例分派、DNS 过滤候选和 --test |
| src/lib/transactions.py | 写前日志、文件摘要、快照、冲突、原子替换 |
| src/lib/host.py | 系统只读探测、服务、nftables、路由归属、回滚调度 |
| src/lib/runtime.py | 统一生命周期状态机、安装、恢复、确认、清理 |
| src/lib/observability.py | 审计、健康、脱敏、保留期及容量 |
| tools/build.py | 确定性单文件打包与载荷完整性 |

模块没有在导入时操作网络。管理器依赖宿主机适配器；测试的 SandboxHost 不执行 systemctl、ip 或 nft，结果明确标记 simulation。真实隔离测试单独使用实际后端和内核，不混同模拟结果。

## 待应用数据

state.json 原子保存 schema、revision、排序后的 domains 和最近 200 个成功差异。输入全量校验后才获取 write.lock、合并和提交。清单、修订、历史在同一文件中提交；--dry-run 不创建目录或锁。

待应用数据与运行状态分开。apply 使用读取时的清单快照；等待确认期间继续编辑清单不会改变正在确认的候选，也不会丢失之后的编辑。status 区分已提交状态与临时生效状态。

## 运行状态与事务

runtime.json 记录安装/启用状态、后端版本、策略、清单、当前事务、文件与内核资源归属、依赖记录及可变缓存。runtime.lock 串行化生命周期操作。

事务目录包含 journal.json、before-N、after-N 和 timer-manifest.json。修改前记录旧文件摘要、权限、UID/GID及候选内容；文件写入后通过 fsync 和原子替换提交。写前日志允许在文件已修改、进程尚未更新状态时识别并恢复。

状态流程为 `prepared → rollback_armed → applying → awaiting_confirm → committed`；恢复使用 `restoring → restored/restore_failed`。confirm 先持久化 committed，再写运行状态并取消该事务定时器；迟到的恢复任务会重放已提交状态，不撤销已确认事务。

恢复前完整检查冲突和所需快照。恢复失败不删除快照，不把失败伪装为成功。最近 5 个已完成事务按数量保留，同时保护当前、前一恢复基线和所有未解决事务，因此总数可能超过 5。

## 资源边界

不可变文件有摘要与 POSIX 元数据；FakeIP 数据库声明为项目私有可变资源。nftables 使用唯一安装标识，只操作自己的表。IP 规则记录优先级、表和选择条件；清理只接受已记录的残留，不整体清空规则。TUN 自动链路本地地址和内核 detached 标记不当作永久配置变化。

独立恢复任务以唯一 ID 命名。APT 的临时 policy-rc.d 修改也有独立快照和恢复任务，包管理器仍持锁时保留禁止自启策略并重试。新增共享包保留且记录，不在回滚或 purge 中盲目删除。

systemd、APT、journal 和宿主机网络完整组合仍需目标系统验收。当前独立命名空间测试覆盖后端数据路径，不能证明所有发行版的 PID 1 集成已经可用。

# sing-box 1.14.1 候选配置与边界

当前管理器为 v6only 0.3.1-dev。本页说明 `config render` 生成的无入口候选与固定版本字段依据；生命周期管理器另有实际 TUN/FakeIP 渲染器，运行路径和测试见 [网络设计](network-design.md)。不要把两类配置混淆。

## 版本依据

2026-09-19 UTC 查询 [官方最新发布 API](https://api.github.com/repos/SagerNet/sing-box/releases/latest)，得到 v1.14.1，非预发布，发布时间 2026-09-15T00:06:50Z。实际固定的是 [v1.14.1 标签](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1)，不是会随时间改变的 latest。

曾保存对应标签的官方文档、关键源码和来源摘要清单（快照不随仓库分发）。实现基于这些资料核实字段后编写，没有沿用已移除的旧 `domain_strategy`。

| 候选字段 | 固定版本官方依据 | 用途与限制 |
| --- | --- | --- |
| `route.rules.domain` | [路由规则](https://github.com/SagerNet/sing-box/blob/v1.14.1/docs/configuration/route/rule.md) | 精确匹配 |
| `domain_regex` | 同上 | RE2 兼容锚定正则，表达仅子域，不使用可能包含根域的后缀匹配 |
| `type: logical, mode: and` | 同上 | 域名条件与 IPv4 目标条件取交集；普通规则中 domain 与 ip_cidr 是 OR，不能直接平铺 |
| `action: sniff` | [路由动作](https://github.com/SagerNet/sing-box/blob/v1.14.1/docs/configuration/route/rule_action.md) | 识别受支持协议，不能保证识别 ECH/任意应用 |
| `action: resolve, strategy: ipv6_only` | 同上 | 命中时仅解析 IPv6，实际适用范围见下文 |
| `domain_resolver` | [拨号字段](https://github.com/SagerNet/sing-box/blob/v1.14.1/docs/configuration/shared/dial.md) | direct 出站使用明确上游和解析策略，避免旧字段 |
| `dns.servers.type: udp` | [UDP DNS](https://github.com/SagerNet/sing-box/blob/v1.14.1/docs/configuration/dns/server/udp.md) | 上游必须显式指定 IP；生成/校验不向它发起查询 |
| `dns.reverse_mapping` | [DNS](https://github.com/SagerNet/sing-box/blob/v1.14.1/docs/configuration/dns/index.md) | 仅准备映射配置；无 DNS 入口的候选不会获得真实映射 |

`domain_resolver` 格式引用 DNS 路由动作；该文档中的 `strategy` 在 1.14 标记弃用并计划在 1.16 移除。1.14.1 官方 check 接受当前配置，但这不是未来版本兼容承诺。

## 规则顺序

1. 协议嗅探。
2. 命中域名且目标为 IPv4/IPv4-mapped 时拒绝。使用逻辑 AND，不扩大为全部 IPv4 阻断。
3. 命中域名执行 `resolve`，策略 `ipv6_only`。
4. 再次检查同一拒绝条件，防御候选路由阶段已有 IPv4 解析结果的情形。
5. 命中域名转到 `strict-ipv6` direct 出站，其域名解析策略也为 `ipv6_only`。
6. 其他可解析的域名使用 `prefer_ipv6`，最终走默认 direct 出站。

空清单不生成域名匹配为空的严格规则，避免意外成为全匹配。根域与通配分别保留。生成规则的 Python 语义测试验证误匹配边界，官方 check 验证正则可编译；尚未执行真实流量规则匹配测试。

## 关键限制

官方 [route/route.go](https://github.com/SagerNet/sing-box/blob/v1.14.1/route/route.go) 的 `actionResolve` 只在 `metadata.Destination.IsDomain()` 为真时执行解析。嗅探得到的 `metadata.Domain` 不自动等同于域名形式的目标地址。因此不能只设置 IPv6 解析策略就宣称所有命中 IPv4 连接会改连 IPv6。

当前候选遇到已识别域名的 IPv4 目标会拒绝，**不会自动把这类连接改拨 IPv6**。这可能让本来有 AAAA 的服务仍连接失败。DNS 映射、FakeIP 或其他域名目标转换方案、IPv4-mapped 行为、TCP/UDP、地址缓存和故障保护，需要下一阶段在授权的隔离网络环境中验证。

候选没有 inbounds，不创建 TUN、代理端口或 DNS 监听，因此当前不会实际执行上述路由策略。它也没有管理流量绕过、独立定时回滚、防泄漏规则、动态地址处理或完整服务日志，不能作为生产配置部署。对无法识别域名的直连 IP、独立 DoH、ECH、已有连接和未接管命名空间，仍不得声称严格控制。

## 候选包与校验

候选包包含 schema、backend、backend_version、profile、source_revision、domains、dns_upstream、config_sha256、config，`runtime_verified` 必须为 false。纯配置 JSON 按固定排序和紧凑编码计算 SHA-256。相同清单、修订和上游会产生相同候选，不写入时间戳。

候选是导出时的快照；静态校验不比较当前待应用清单是否已变更，也不证明来源身份。修订号和摘要是后续事务核对的输入，不能单凭一次 check 成功批准应用过时配置。

`config render` 默认输出到终端；`--output` 只允许新文件，以 0600 原子创建，不改动清单历史。`--dry-run` 不创建状态目录、锁、候选文件或审计。

`config validate` 先根据包内已规范化的域名和上游完整重生成，再逐字段比对规范化 JSON。修改 inbounds、日志输出、远程规则集、版本、运行验证标记等，即使重新计算摘要也被拒绝。此入口不接受通用 sing-box 配置。

官方 [check 实现](https://github.com/SagerNet/sing-box/blob/v1.14.1/cmd/sing-box/cmd_check.go) 会调用 `box.New`，然后关闭实例，不调用启动流程。因此仍须限制候选内容，不能假设任何配置的 check 都无文件副作用。我们的临时纯配置没有文件输出或运行入口。

校验顺序：内部结构复核 → 明确指定的可信二进制 version → 严格匹配 1.14.1 → 私有临时目录中的纯配置 → `sing-box check -c` → 清理临时目录。外部调用有 15 秒超时，不使用 shell。返回结果明确区分 `syntax_checked: true` 与 `runtime_verified: false`。`--dry-run` 只复核结构并说明计划，不启动 version/check，也不创建临时目录。

指定 `--binary` 意味着执行该文件，必须来自可信来源；版本字符串本身不证明软件真实性。项目提供显式下载工具，将固定官方归档与 GitHub 发布摘要核对后，只提取预期普通文件到 `.cache/`。官方资产列表没有独立签名文件，本轮没有签名验证。自动检查会核对缓存二进制摘要后才进行官方静态测试。

## 验证与下一步

官方校验覆盖空清单、精确、通配、混合、punycode、IPv4/IPv6 DNS 上游和完整示例；同时验证无效出站类型返回失败。所有 DNS 地址使用文档地址，不做解析、TCP/TLS 或业务请求。

事务、资源归属、生命周期和真实隔离网络测试现已实现。目标系统的完整安装、systemd、SSH、真实 DynamicV6 及重启验收仍未执行，不能以本页的静态校验代替。

## 运行配置补充

运行渲染器使用 gVisor 栈、仅本机输出接口 lo 与选定 UID、FakeIP、项目专属 DNS 入口、显式 UID 路由和独立 nftables 故障保护。DNS 模式设为 disabled，防止后端自行修改 systemd-resolved。FakeIP 缓存使用固定版本官方 experimental.cache_file/store_fakeip 字段；校验时重定向到临时路径，隔离测试也使用私有路径，不打开宿主机运行数据库。

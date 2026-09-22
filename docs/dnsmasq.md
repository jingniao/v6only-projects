# dnsmasq 2.91 备用后端

采用三个独立实例：front 接收本地查询，filtered 使用全局 filter-A，normal 普通解析。实例均仅绑定回环地址，使用 no-resolv、no-hosts 和明确上游，不复用或覆盖系统现有 dnsmasq 实例。

front 默认转给 normal。每个相关域名分别生成 `/根域/` 与 `/*.根域/` 分派，结合父级通配继承计算根域和子域的实际策略。2.91 官方打包手册明确 `/*.example.com/` 不含根域；真实二进制测试确认更具体的子域分派能表达精确域名排除。根域与通配在用户清单中仍分别保留。

没有使用不存在的 `filter-A=/域名/`。filtered 中 filter-A 全局过滤 A，filter-rr=64,65 移除 SVCB/HTTPS，避免保留 IPv4 地址提示。CNAME 可以保留，其回复中的 A 会被过滤；AAAA 保留。

验证包括精确根域、不含根域的多级通配、相似域名、重叠规则、CNAME、AAAA、HTTPS/SVCB，以及 filtered 停止后命中请求不回退 normal。测试使用本地合成 DNS 上游，不查询真实 AI 站点。

版本固定 2.91，其他版本不自动兼容。候选经过完整重生成比较，不能添加未知配置项。来源为 Debian 官方 dnsmasq-base 2.91-1+deb13u2 测试包，摘要见 tools/dnsmasq-release.json；手册快照见 reference/runtime/dnsmasq-2.91.man。

启用/切换必须确认：DNS 约束无法提供与 TUN IPv6-only 出站相同的保障。系统代理解析、DoH、缓存 IPv4 和直接 IP 不受这一过滤机制保证。

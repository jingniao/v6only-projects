# 模板与候选

singbox-candidate.example.json 是无入口的独立候选包，包含元数据与纯配置，适合官方静态校验。它不能直接当作完整 TUN 部署文件，192.0.2.53 是文档占位上游。

实际 TUN、dnsmasq、nftables、systemd 和日志配置由受版本管理的渲染器生成，避免静态副本漂移。使用 install --policy examples/policy.json.example --dry-run 可查看完整计划，再按实际环境替换策略输入。

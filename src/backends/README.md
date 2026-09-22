# 后端

singbox.py 实现 1.14.1 的独立候选、TUN/FakeIP 运行配置和官方校验。dnsmasq.py 实现 2.91 三实例 DNS 分派/过滤。启动、事务、服务与恢复统一由 lib/runtime.py 和 lib/host.py 管理，后端模块导入时不产生系统副作用。

真实隔离后端测试与模拟生命周期测试分别记录；目标系统部署仍须验收。

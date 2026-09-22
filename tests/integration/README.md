# 隔离集成测试

test_dnsmasq.py 使用已验证 2.91 二进制，临时监听回环高端口，测试三实例真实 DNS 语义和失败行为，不修改系统解析器。

test_tun_namespace.py 通过 unshare 创建独立网络命名空间，并验证 inode 与宿主机不同。私有 veth、路由、nftables、TUN、DNS、TCP/TLS/UDP 服务仅在隔离空间内存在。第二个命名空间充当上游，额外命名空间验证相同 UID 的转发流量不被接管。退出时清理测试进程组。

运行：python3 -B tools/check.py --integration。需要已验证的缓存、ip/nft/unshare/openssl、TUN 和相应 namespace 权限。不能隔离时测试失败，不在默认网络中替代执行。真实 PID 1、APT、SSH、DynamicV6 和服务器重启另行验收。

# 网络共享器

网络共享器是一款 macOS IPv4 网络共享工具：通过所选端口把 Mac 的 Wi-Fi 连接共享给其他设备。它提供 Wi-Fi 直连、可选认证的本机 SOCKS5 代理、自定义首选和备用 DNS，并尝试在受支持的 iPhone USB 端口断开后恢复连接。

本项目仍依赖用户从合法安装的 Parallels Desktop 环境自行提供 `prl_naptd` 和兼容的 QtCore、QtNetwork 运行库；此仓库不包含它们，也不授予它们的使用或分发许可。仓库仅包含应用自身的源码和图标生成代码。复制、移植或分发打包后的应用前，请自行确认相关组件的许可。

## 使用和限制

- 图形界面、iPhone USB 及恢复操作见 [使用说明](使用说明.md)。启动共享需要 macOS 管理员授权。
- 直连将共享流量绑定到选择的 Wi-Fi 接口，避免使用系统默认 VPN 路由和系统代理设置；底层拦截软件与上游透明代理不在本程序控制范围内。
- SOCKS5 模式将 TCP 和普通 DNS 交给本机指定端口；非 DNS UDP 会被阻断。代理软件自身的规则仍然有效。
- 仅支持 IPv4；创建无线热点、SSID 和密码配置尚未实现。
- 为避免重启后重复分配地址，DHCP 租约保存在仅 root 可访问的应用专用目录，可能包含设备 MAC 地址和租约信息；退出应用不会删除这些记录，详见 [使用说明](使用说明.md)。
- 此项目使用闭源组件、动态库拦截和系统接口；不同 macOS 或 Parallels 版本可能不兼容。已构建的应用只在一台 Apple 芯片 Mac 上测试，其他电脑和系统版本需要另行验证。
- 本地构建使用 ad-hoc 签名，未使用 Developer ID 签名或 Apple 公证，不等同于完成公开发行准备。

## 构建

需要 Apple 芯片 Mac、macOS 14 或更高版本、Xcode Command Line Tools，以及自行准备的、与 `prl_naptd` 兼容的 arm64 QtCore 和 QtNetwork framework。macOS 14 是构建目标，不表示已验证所有后续系统版本。默认从 `/Applications/Parallels Desktop.app/Contents` 寻找组件。

```sh
# 可选：Parallels 不在默认位置时指定。
export NETWORKSHARER_PARALLELS_APP="/path/to/Parallels Desktop.app"
# 可选：单独指定兼容的运行库目录，里面包含 QtCore.framework 和 QtNetwork.framework。
export NETWORKSHARER_QT_FRAMEWORKS="/path/to/Frameworks"
python3 build_app.py
```

也可通过 `NETWORKSHARER_DAEMON` 单独指定 `prl_naptd`，通过 `NETWORKSHARER_OUTPUT_DIR` 指定输出目录。构建脚本会检查 arm64 架构和运行库直接依赖，遇到不在允许列表中的动态库会拒绝打包；该检查不是对组件来源或安全性的完整证明。默认输出 `build/网络共享器正式版/网络共享器.app`；如果同一路径的应用正在运行，构建会停止以避免覆盖。源码构建时会生成图标，不需额外下载图片。

## 测试

`Tests` 目录提供 DNS、SOCKS5 认证、接口变化、重连、进程清理、负载等本地测试。部分脚本需要先构建应用，其结果取决于系统环境；不要把回环压力结果当作 USB 或互联网实际吞吐。`Tests/build_validation_app.py` 可构建需要管理员授权的本地集成验证界面：它会临时创建虚拟网络接口、启动共享并测试 DHCP 和清理，运行期间可能中断现有共享。测试完成后请检查结果与系统状态。

测试结果不能证明程序在所有系统、网络条件或长时间运行下均稳定，也不能证明闭源依赖不存在内存或其他缺陷。

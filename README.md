# 局域网代理共享器（网络共享器分支）

这是“网络共享器”的分支版本：在原有共享功能之外，新增**局域网 SOCKS5 代理**，让手机与 Mac 连同一个 Wi‑Fi 时，只由 Mac 完成网页认证，手机通过 Mac 的已认证连接访问互联网。

网络共享器让 Mac 将已连接的 Wi‑Fi 网络共享给其他设备。对于需要通过网页认证的校园网、酒店等网络，先在 Mac 上完成认证，再将连接共享给手机或其他设备，可以减少逐台登录的麻烦。下游设备使用独立子网，上游网络通常只直接看到 Mac 的网络地址，有助于减少新设备直接暴露在上游局域网。

能否共享以及是否需要再次认证取决于网络运营方的策略；本应用不保证对所有网络均有效，也不提供匿名性保证。

## 功能

- 通过可用的共享端口向设备提供 IPv4 网络连接；支持的 iPhone USB 端口可以通过数据线连接 iPhone。
- **Wi‑Fi 直连**：将共享连接绑定到选定的物理 Wi‑Fi 接口，不使用系统代理或系统默认 VPN 路由；无法连接时不会自动改用代理。
- **SOCKS5 代理**：可以手动指定本机代理端口，按需填写用户名和密码；TCP 和普通 DNS 请求通过指定代理。代理模式不转发非 DNS 的 UDP。
- 手动指定首选及备用 DNS；启动时读取当前 Wi‑Fi 的 DNS。
- 自动更新端口列表，并尝试在受支持的设备重新连接后恢复共享。
- **局域网隧道（分支新增）**：在 Mac 的 Wi‑Fi 地址上监听一个 SOCKS5 端口，供同一网络内的客户端（手机、平板或电脑）填写。只监听 Wi‑Fi 地址，不监听其他接口；必须设置用户名和密码；可单独使用，不必选择共享端口。直连模式支持 TCP 与 UDP；上游 SOCKS5 模式下隧道仅转发 TCP（UDP 会被明确拒绝），物理共享端口的上游 UDP 在服务支持时可用，失败时不回退直连。

图形界面和常见问题见 [使用说明](使用说明.md)。开启共享需要 macOS 管理员授权。无线热点、SSID 设置和 IPv6 暂不支持；不同设备和端口的支持情况需实际验证。

## 与原项目隔离

本分支把运行时资源全部换成了自己的名字，可与原项目同时安装、同时运行：

| 项目 | 原项目 | 本分支 |
| --- | --- | --- |
| 应用标识 | `com.local.networksharer` | `com.local.lansharer` |
| 会话目录 | `/private/tmp/networksharer.*` | `/private/tmp/lanproxy.*` |
| 会话锁 | `com.local.networksharer.session.lock` | `com.local.lansharer.session.lock` |
| DHCP 租约 | `/private/var/db/com.local.networksharer` | `/private/var/db/com.local.lansharer` |
| 共享网段 | `172.30.78.0/24` | `172.30.79.0/24` |
| 应用包名 | `网络共享器.app` | `局域网代理共享器.app` |

构建与测试全部在本目录内完成，输出写入本目录的 `build/`。

## 项目状态

独立网络核心已经接入，应用包包含运行时组件；设备兼容性、异常恢复与发行材料仍在验证。不同版本和环境的测试结果不能互相替代。

目标平台为 Apple 芯片 Mac，编译目标为 macOS 14 或更高版本；具体系统兼容性须在相应设备上实测。当前本地构建没有 Developer ID 签名与 Apple 公证，在其他 Mac 上打开时可能受到系统安全检查限制。

## 界面迭代构建（不打断当前共享）

本工作区已有可运行应用时，可只重编译 Swift 界面，输出到新的 `build/ui-candidate-时间戳/`：

```sh
python3 -I Tools/build_ui_candidate.py
```

不覆盖原候选包、不下载运行库。隧道用户名默认 `Mac`，成功启动后账号随应用偏好设置记住；运行状态不再依赖密码输入框的内容。见 [使用说明](使用说明.md)。

```sh
python3 -I Tests/test_lan_ui.py
```

状态、凭据及原生视图测试均使用合成数据；钥匙串测试使用工作区内新建的独立钥匙串，不读取真实保存账号。

## 构建与测试

构建需要 Apple 芯片 Mac、macOS 14 或更高版本及 Xcode Command Line Tools。先准备经过校验的开源运行库，再构建应用：

```sh
python3 Tools/prepare_runtime.py --packages /private/tmp/networksharer-packages \
  --output /private/tmp/networksharer-runtime --download-missing
export NETWORKSHARER_GLIB_PREFIX=/private/tmp/networksharer-runtime/glib
export NETWORKSHARER_PROTO_RUNTIME=/private/tmp/networksharer-runtime/runtime
python3 build_app.py
```

构建产物和完整的运行库会放入 `build/standalone-candidate/局域网代理共享器.app`。第三方许可、源码和动态库替换说明见 [运行库来源](ThirdParty/RuntimeLicenses/SOURCES.md)。`Tests` 目录包含代理、DNS、地址分配与会话清理等测试，部分测试需要特定环境或管理员授权。

只有实际完成设备、异常恢复、运行库依赖和系统兼容性验证后，才能确定发布包的功能范围；本机回环测试不代表设备或互联网的实际吞吐。

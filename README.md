# 局域网代理共享器

把 Mac 的 Wi‑Fi 连接共享给手机、平板或其他电脑。设备可通过 iPhone USB 或兼容的以太网端口接入，也可在同一局域网内连接带认证的 SOCKS5 代理。适用于可以共享已连接网络的场景，例如 Mac 已完成 Wi‑Fi 网页认证、还想让其他设备上网时。能否使用取决于网络运营方的规则，以及设备之间是否可以通信。

## 下载与安装

适用于 **Apple 芯片 Mac**，系统要求 **macOS 14 或更新版本**。应用包含所需的运行库，下载后即可安装。

1. 前往 [GitHub Releases](https://github.com/payara-wy/network-sharer/releases/latest) 下载 `.dmg` 安装包。
2. 打开安装包，将「局域网代理共享器」拖入「应用程序」，再从 Finder 的「应用程序」中打开它。
3. 此版本采用 ad hoc 签名，**未经 Apple 公证**。如果首次启动提示无法验证开发者或 Apple 无法检查该应用，确认安装包来自本仓库且完整后，打开「系统设置 → 隐私与安全性」，向下滚动并点「仍要打开」，再在提示框中确认。按钮只会在尝试打开应用后出现。详见 [Apple 的打开应用说明](https://support.apple.com/zh-cn/102445)。

发布页同时提供 `SHA256SUMS.txt`，可在终端运行 `shasum -a 256 文件名.dmg` 并比对结果。

启动共享需要 macOS 管理员授权。首次打开时的安全确认和启动共享时的管理员授权是两项独立操作。

## 如何共享

- **USB 或以太网**。连接设备，在应用中选中可用的物理共享端口，再开启「互联网共享」。通过 iPhone USB 接入时，首次连接需在手机上确认信任 Mac。设备使用独立的 IPv4 子网，应用会在可识别的设备重新接入时尝试恢复共享。
- **局域网隧道**。在应用中启用「局域网隧道」，设置端口、用户名和密码，再开启共享。客户端与 Mac 接入可互通的网络，在支持 SOCKS5 的客户端中填写界面显示的地址和账号。只用隧道时无需选物理端口。

两种接入方式均可选择 **Wi‑Fi 直连**或 **SOCKS5 上游**。直连将转发连接绑定到所选的物理 Wi‑Fi 接口。上游模式将流量交给指定的本机 SOCKS5 端口，支持按需填写上游账号。连接失败时应用会报错或丢弃相应流量。

| 设备接入方式 | Wi‑Fi 直连 | SOCKS5 上游 |
| --- | --- | --- |
| USB 或以太网 | TCP、UDP | TCP、普通 DNS。其他 UDP 需要上游支持 |
| 局域网隧道 | TCP、UDP | TCP，拒绝 UDP 关联 |

应用会读取所选 Wi‑Fi 的 DNS，也可手动设置首选和备用 IPv4 DNS。局域网 SOCKS5 连接本身不加密，隧道账号与密码以普通应用偏好设置保存，请在可信网络中使用。当前支持 IPv4，未提供无线热点、SSID 配置和 IPv6 共享。

[使用说明](使用说明.md)包含设置步骤和故障排查。[验证报告](验证报告.md)记录了构建、回环验证和设备兼容性测试的范围。

## 从源码构建

需要 Apple 芯片 Mac、macOS 14 或更新版本，以及 Xcode Command Line Tools。以下命令准备并校验开源运行库，再构建应用：

```sh
python3 Tools/prepare_runtime.py --packages /private/tmp/networksharer-packages \
  --output /private/tmp/networksharer-runtime --download-missing
export NETWORKSHARER_GLIB_PREFIX=/private/tmp/networksharer-runtime/glib
export NETWORKSHARER_PROTO_RUNTIME=/private/tmp/networksharer-runtime/runtime
python3 build_app.py
```

应用输出到 `build/standalone-candidate/局域网代理共享器.app`。`Tests/` 中包含代理、DNS、地址分配、会话清理和界面测试，部分测试需 macOS 管理员权限或实际网络接口。发布页提供运行库对应源码。依赖版本、许可和动态库替换方法见[第三方运行库说明](ThirdParty/RuntimeLicenses/SOURCES.md)。

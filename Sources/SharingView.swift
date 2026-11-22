import SwiftUI
import AppKit

private struct SettingsRow<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(title).foregroundStyle(.secondary).frame(width: 82, alignment: .leading)
            content.frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.system(size: 13))
    }
}

private struct SettingsSection<Content: View>: View {
    let title: String
    let symbol: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: symbol)
                .font(.system(size: 14, weight: .semibold))
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 20)
    }
}

@MainActor private final class SharingPresentation: ObservableObject {
    @Published var showLANSecret = false
    @Published var showHelp = false
    @Published var showDNS: Bool
    @Published var copied = false
    init(showDNS: Bool = false) { self.showDNS = showDNS }
}

struct ContentView: View {
    @ObservedObject var model: HotspotModel
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var presentation: SharingPresentation
    init(model: HotspotModel, showDNS: Bool = false) {
        self.model = model
        _presentation = StateObject(wrappedValue: SharingPresentation(showDNS: showDNS))
    }

    private var stateLabel: String {
        switch model.sharingState {
        case "running": return "共享中"
        case "waiting": return "等待物理端口"
        case "starting": return "正在启动"
        case "stopping": return "正在停止"
        case "error": return "需要处理"
        default: return "已关闭"
        }
    }
    private var stateColor: Color {
        switch model.sharingState {
        case "running": return .green
        case "starting", "waiting", "stopping": return .orange
        case "error": return .red
        default: return .secondary
        }
    }
    private var addressAvailable: Bool { !model.wifiAddress.isEmpty && model.wifiAddress != "未连接" }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    upstreamSection
                    Divider()
                    lanSection
                    Divider()
                    portsSection
                    Divider()
                    addressesSection
                    Divider()
                    checksSection
                }
                .padding(.horizontal, 26)
                .padding(.bottom, 16)
            }
        }
        .frame(minWidth: 640, idealWidth: 720, minHeight: 620, idealHeight: 800)
        .background(Color(nsColor: .windowBackgroundColor))
        .onChange(of: scenePhase) { if scenePhase != .active { presentation.showLANSecret = false } }
        .onChange(of: model.lanProxyEnabled) { presentation.showLANSecret = false }
        .onChange(of: model.wifiAddress) { presentation.copied = false }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 14) {
                Image(systemName: "personalhotspot")
                    .font(.system(size: 25, weight: .medium)).foregroundStyle(.tint)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("互联网共享").font(.system(size: 20, weight: .semibold))
                    HStack(spacing: 6) {
                        StatusDot(color: stateColor)
                        Text(stateLabel).font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Toggle("开启互联网共享", isOn: Binding(
                    get: { model.isBusy },
                    set: { enabled in enabled ? model.startSharing() : model.stopSharing() }
                ))
                .labelsHidden().toggleStyle(.switch).controlSize(.large)
                .accessibilityLabel("开启互联网共享")
                .disabled(model.sharingState == "starting" || model.sharingState == "stopping" || (!model.isBusy && !model.canStart))
            }
            if model.sharingState == "error" {
                Label(model.sharingMessage, systemImage: "exclamationmark.circle")
                    .font(.system(size: 12)).foregroundStyle(.red).textSelection(.enabled)
            } else if let hint = model.startHint {
                Text(hint).font(.system(size: 12)).foregroundStyle(.secondary)
            } else if model.isBusy && model.sharingState != "running" {
                Text(model.sharingMessage).font(.system(size: 12)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 26).padding(.vertical, 18)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var upstreamSection: some View {
        SettingsSection(title: "上游连接", symbol: "wifi") {
            SettingsRow(title: "Wi-Fi 接口") {
                Picker("Wi-Fi 接口", selection: $model.sourceDevice) {
                    if model.wifiSources.isEmpty { Text("未检测到 Wi-Fi").tag("") }
                    ForEach(model.wifiSources) { adapter in Text("Wi-Fi (\(adapter.device))").tag(adapter.device) }
                }
                .labelsHidden().frame(maxWidth: 230)
                .disabled(model.isBusy || model.wifiSources.isEmpty)
                .onChange(of: model.sourceDevice) {
                    model.refreshNetworkInfo(); model.loadWiFiDNSIfNeeded(); model.refreshDNSCheck()
                }
            }
            SettingsRow(title: "出口方式") {
                Picker("出口方式", selection: $model.routeMode) {
                    Text("Wi-Fi 直连").tag("direct")
                    Text("SOCKS5 上游").tag("socks5")
                }
                .labelsHidden().pickerStyle(.segmented).disabled(model.isBusy)
                .onChange(of: model.routeMode) { model.refreshProxyCheck(showPending: true); model.refreshDNSCheck() }
            }
            if model.routeMode == "direct" {
                Text("流量从所选 Wi-Fi 发出，不使用系统代理或 VPN 路由。")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                SettingsRow(title: "本机代理") {
                    HStack {
                        Text("127.0.0.1 :").monospacedDigit()
                        TextField("1082", text: $model.proxyPort).frame(width: 76)
                            .accessibilityLabel("上游代理端口")
                            .onChange(of: model.proxyPort) { model.refreshProxyCheck(showPending: true); model.refreshDNSCheck() }
                        Toggle("需要认证", isOn: $model.useAuthentication)
                            .onChange(of: model.useAuthentication) { model.refreshProxyCheck(showPending: true); model.refreshDNSCheck() }
                    }.disabled(model.isBusy)
                }
                if model.useAuthentication {
                    SettingsRow(title: "上游用户名") { TextField("用户名", text: $model.proxyUsername).disabled(model.isBusy) }
                    SettingsRow(title: "上游密码") { SecureField("本次使用，不保存", text: $model.proxyPassword).disabled(model.isBusy) }
                }
                Text("TCP、DNS 与 UDP 走上游代理；UDP 需上游支持，不回退直连。")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            DisclosureGroup(isExpanded: $presentation.showDNS) {
                VStack(spacing: 10) {
                    SettingsRow(title: "首选 DNS") {
                        HStack(spacing: 8) {
                            LevelRing(level: model.dnsPrimaryLevel)
                            TextField("IPv4 地址", text: Binding(get: { model.dnsServer }, set: { model.setDNS($0, secondary: false) }))
                        }
                    }
                    SettingsRow(title: "备用 DNS") {
                        HStack(spacing: 8) {
                            LevelRing(level: model.dnsSecondaryLevel)
                            TextField("可选", text: Binding(get: { model.dnsSecondary }, set: { model.setDNS($0, secondary: true) }))
                        }
                    }
                }.disabled(model.isBusy).padding(.top, 12)
            } label: {
                HStack {
                    Text("DNS 设置")
                    Spacer()
                    Text(model.dnsSummary).monospacedDigit().foregroundStyle(.secondary)
                }
            }.font(.system(size: 12))
        }
    }

    private var lanSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("局域网隧道", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.system(size: 14, weight: .semibold))
                Spacer()
                Toggle("启用局域网隧道", isOn: $model.lanProxyEnabled)
                    .labelsHidden().toggleStyle(.switch).controlSize(.small)
                    .accessibilityLabel("启用局域网隧道").disabled(model.isBusy)
            }
            Text("客户端  →  Mac  →  上游网络")
                .font(.system(size: 13)).foregroundStyle(.secondary)
            if model.lanProxyEnabled {
                VStack(alignment: .leading, spacing: 13) {
                    HStack {
                        Text("客户端连接信息").font(.system(size: 13, weight: .semibold))
                        Spacer()
                        Text(model.lanCheck.level == .good ? "已就绪" : (model.isBusy ? "未就绪" : "待启动"))
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(model.lanCheck.level == .good ? Color.green : Color.secondary)
                    }
                    SettingsRow(title: "类型") { Text("SOCKS5") }
                    SettingsRow(title: "服务器") {
                        HStack {
                            Text(addressAvailable ? model.wifiAddress : "请先连接 Wi-Fi")
                                .font(.system(size: 13, weight: .regular)).textSelection(.enabled)
                            Spacer()
                            Button {
                                NSPasteboard.general.clearContents()
                                presentation.copied = NSPasteboard.general.setString(model.wifiAddress, forType: .string)
                            } label: {
                                Label(presentation.copied ? "已复制" : "复制", systemImage: presentation.copied ? "checkmark" : "doc.on.doc")
                            }
                            .disabled(!addressAvailable).controlSize(.small)
                            .accessibilityLabel("复制服务器地址")
                        }
                    }
                    SettingsRow(title: "端口") {
                        if model.isBusy {
                            Text(model.lanPortText).textSelection(.enabled)
                        } else {
                            TextField("1080", text: $model.lanProxyPort)
                                .frame(width: 94)
                                .accessibilityLabel("局域网监听端口")
                                .onSubmit { model.normalizeLanPort() }
                                .onChange(of: model.isBusy) { if !model.isBusy { model.normalizeLanPort() } }
                        }
                    }
                    SettingsRow(title: "用户名") {
                        if model.isBusy { Text(model.lanProxyUsername).textSelection(.enabled) }
                        else {
                            TextField("Mac", text: $model.lanProxyUsername).accessibilityLabel("局域网隧道用户名")
                        }
                    }
                    SettingsRow(title: "密码") {
                        HStack {
                            Group {
                                if model.isBusy {
                                    if presentation.showLANSecret {
                                        Text(model.lanProxyPassword).textSelection(.enabled)
                                    } else {
                                        Text("••••••••").accessibilityLabel("密码已隐藏")
                                    }
                                } else if presentation.showLANSecret {
                                    TextField("必填", text: $model.lanProxyPassword)
                                } else {
                                    SecureField("必填", text: $model.lanProxyPassword)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .accessibilityLabel("局域网隧道密码")
                            Button { presentation.showLANSecret.toggle() } label: {
                                Image(systemName: presentation.showLANSecret ? "eye.slash" : "eye")
                                    .frame(width: 24, height: 20)
                            }
                            .buttonStyle(.borderless)
                            .help(presentation.showLANSecret ? "隐藏密码" : "显示密码")
                            .accessibilityLabel(presentation.showLANSecret ? "隐藏密码" : "显示密码")
                        }
                    }
                    if model.credentialWarning {
                        Label(model.credentialNotice, systemImage: "exclamationmark.triangle")
                            .font(.system(size: 11)).foregroundStyle(.orange)
                    }
                    if !model.isBusy, let issue = model.lanIssue {
                        Text(issue).font(.system(size: 12)).foregroundStyle(.orange)
                    }
                }
                .font(.system(size: 13, weight: .regular))
                .padding(16)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.08)))

                if model.routeMode == "socks5" {
                    Text("上游代理模式下，局域网隧道仅支持 TCP；UDP 需要改用 Wi-Fi 直连，或使用物理共享端口。")
                        .font(.system(size: 12)).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                }
                HStack(alignment: .top, spacing: 12) {
                    Text("客户端新建 SOCKS5 连接，填写以上信息并启用代理。")
                        .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Button { presentation.showHelp.toggle() } label: { Image(systemName: "questionmark.circle") }
                        .buttonStyle(.borderless).accessibilityLabel("局域网隧道帮助")
                        .popover(isPresented: $presentation.showHelp) {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("连接须知").font(.headline)
                                Text("先在 Mac 完成 Wi-Fi 认证。客户端能否连接 Mac 取决于网络是否允许设备互通；访客网络的客户端隔离可能阻止连接。")
                                Text("SOCKS5 不加密局域网传输，请仅在可信网络使用。直连支持 TCP / UDP；SOCKS5 上游的 UDP 取决于上游服务支持。账号通过应用偏好设置记住，不加密保存。")
                            }.font(.system(size: 12)).frame(width: 300).padding(20)
                        }
                }
            } else {
                Text("让同一 Wi-Fi 下的客户端通过 Mac 连接互联网。")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 20)
    }

    // Physical ports deliberately precede network addresses.
    private var portsSection: some View {
        SettingsSection(title: "物理共享端口", symbol: "cable.connector") {
            Text("USB 或以太网共享时选择；仅使用局域网隧道可不选。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            if model.outputPorts.isEmpty {
                Text("未检测到端口，连接设备后会自动显示。")
                    .font(.system(size: 13)).foregroundStyle(.secondary).padding(.vertical, 4)
            }
            ForEach(model.outputPorts) { adapter in
                HStack(spacing: 12) {
                    Image(systemName: adapter.mobile ? "iphone" : "cable.connector")
                        .foregroundStyle(.secondary).frame(width: 20)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(adapter.displayTitle).font(.system(size: 13, weight: .medium))
                        Text(!adapter.bridgeable ? "暂不支持系统网桥" : (adapter.connected ? "已连接" : "未连接"))
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle(adapter.displayTitle, isOn: Binding(
                        get: { model.selectedDevices.contains(adapter.device) },
                        set: { enabled in
                            if enabled { model.selectedDevices.insert(adapter.device) }
                            else { model.selectedDevices.remove(adapter.device) }
                            model.refreshNetworkInfo()
                        }
                    ))
                    .labelsHidden().toggleStyle(.switch).controlSize(.small)
                    .accessibilityLabel("共享到 " + adapter.displayTitle)
                    .disabled(model.isBusy || !adapter.bridgeable)
                }.padding(.vertical, 3)
            }
        }
    }

    private var addressesSection: some View {
        SettingsSection(title: "网络地址", symbol: "network") {
            AddressRow(title: "Mac Wi-Fi 地址", value: model.wifiAddress)
            AddressRow(title: "Wi-Fi 网段", value: model.wifiNetwork)
            if model.selectedDevices.isEmpty {
                AddressRow(title: "物理共享网段", value: "不使用")
            } else {
                AddressRow(title: "物理共享网段", value: model.sharedNetwork)
                AddressRow(title: "Mac 共享接口", value: model.sharedAddress)
                AddressRow(title: "网关 / DNS", value: model.sharedNetwork == "172.30.79.0/24" ? "172.30.79.1" : "未运行")
                AddressRow(title: "已发现设备", value: model.clientAddresses)
            }
        }
    }

    private var checksSection: some View {
        DisclosureGroup("本地连接检查", isExpanded: $model.showChecks) {
            VStack(alignment: .leading, spacing: 5) {
                ForEach(model.connectionChecks) { ConnectionCheckRow(check: $0) }
                Text("检查本机配置，不代表所有网站均可访问。")
                    .font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 6)
            }.padding(.top, 12)
        }
        .font(.system(size: 13, weight: .medium)).padding(.vertical, 20)
    }
}

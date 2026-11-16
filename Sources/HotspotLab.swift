import SwiftUI
import AppKit
import Foundation
import Darwin
import SystemConfiguration

struct Adapter: Identifiable, Hashable {
    let name: String
    let device: String
    let connected: Bool
    let hasIPv4: Bool
    let mobile: Bool
    let bridgeable: Bool
    var id: String { device }
    var displayTitle: String {
        let compactName = name.replacingOccurrences(of: " ", with: "").lowercased()
        return compactName.contains("(\(device.lowercased()))") ? name : "\(name)  (\(device))"
    }
}

struct CommandResult {
    let status: Int32
    let output: String
    let error: String
}

func runCommand(_ executable: String, _ arguments: [String], environment: [String: String]? = nil) -> CommandResult {
    let task = Process()
    let out = Pipe()
    let err = Pipe()
    task.executableURL = URL(fileURLWithPath: executable)
    task.arguments = arguments
    task.standardOutput = out
    task.standardError = err
    if let environment { task.environment = environment }
    do {
        try task.run()
        let output = out.fileHandleForReading.readDataToEndOfFile()
        let error = err.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return CommandResult(status: task.terminationStatus,
                             output: String(decoding: output, as: UTF8.self),
                             error: String(decoding: error, as: UTF8.self))
    } catch {
        return CommandResult(status: -1, output: "", error: error.localizedDescription)
    }
}

func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

func appleScriptQuote(_ value: String) -> String {
    "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
}

func discoverMobilePorts() -> Set<String> {
    let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/mobile_identity").path
    let result = runCommand(helper, ["--ports"])
    guard result.status == 0 else { return [] }
    return Set(result.output.split(whereSeparator: { $0.isWhitespace }).map(String.init).filter {
        $0.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil
    })
}

struct IPv4Details {
    let address: String
    let network: String
}

func ipv4Details(_ device: String) -> IPv4Details? {
    guard !device.isEmpty else { return nil }
    let result = runCommand("/sbin/ifconfig", [device])
    for line in result.output.components(separatedBy: .newlines) {
        let words = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        guard words.count >= 4, words[0] == "inet", let maskIndex = words.firstIndex(of: "netmask"),
              maskIndex + 1 < words.count else { continue }
        let octets = words[1].split(separator: ".").compactMap { UInt32($0) }
        let maskText = words[maskIndex + 1]
        guard octets.count == 4, octets.allSatisfy({ $0 < 256 }),
              maskText.hasPrefix("0x"), let mask = UInt32(maskText.dropFirst(2), radix: 16) else { continue }
        let ip = octets.reduce(UInt32(0)) { ($0 << 8) | $1 }
        let net = ip & mask
        let network = "\((net >> 24) & 255).\((net >> 16) & 255).\((net >> 8) & 255).\(net & 255)/\(mask.nonzeroBitCount)"
        return IPv4Details(address: words[1], network: network)
    }
    return nil
}

func stateValues(_ path: String) -> [String: String] {
    guard let text = try? String(contentsOfFile: path + "/state", encoding: .utf8) else { return [:] }
    var values: [String: String] = [:]
    for line in text.split(separator: "\n") {
        guard let i = line.firstIndex(of: "=") else { continue }
        values[String(line[..<i])] = String(line[line.index(after: i)...])
    }
    return values
}

func sessionPossiblyActive(_ values: [String: String], statePath: String) -> Bool {
    let state = values["state"] ?? ""
    guard state == "running" || state == "waiting" || state == "starting" else { return false }
    if let text = values["daemon_pid"], let pid = Int32(text), pid > 1 {
        if Darwin.kill(pid, 0) == 0 || errno == EPERM { return true }
        if errno == ESRCH { return false }
        return true
    }
    guard state == "starting" else { return true }
    let attributes = try? FileManager.default.attributesOfItem(atPath: statePath)
    guard let changed = attributes?[.modificationDate] as? Date else { return true }
    return Date().timeIntervalSince(changed) < 90
}

func observedClients(_ bridge: String) -> String {
    guard bridge.hasPrefix("bridge") else { return "未发现" }
    let output = runCommand("/usr/sbin/arp", ["-an", "-i", bridge]).output
    let re = try? NSRegularExpression(pattern: #"\((172\.30\.77\.[0-9]+)\)"#)
    let range = NSRange(output.startIndex..<output.endIndex, in: output)
    let addresses = re?.matches(in: output, range: range).compactMap { match -> String? in
        guard let r = Range(match.range(at: 1), in: output) else { return nil }
        let value = String(output[r])
        return value == "172.30.77.1" || value == "172.30.77.2" ? nil : value
    } ?? []
    let unique = Array(Set(addresses)).sorted()
    return unique.isEmpty ? "未发现" : unique.joined(separator: "、")
}

enum CheckLevel {
    case good, attention, pending
}

struct ConnectionCheck: Identifiable {
    let name: String
    let detail: String
    let level: CheckLevel
    var id: String { name }
}

func validDNSServer(_ text: String) -> Bool {
    var address = in_addr()
    guard text.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return false }
    let first = UInt32(bigEndian: address.s_addr) >> 24
    return first > 0 && first < 224 && first != 127
}

// Read DNS from the selected Wi-Fi service, rather than the system-wide VPN resolver.
func wifiDNSServers(_ device: String) -> [String] {
    guard !device.isEmpty,
          let store = SCDynamicStoreCreate(nil, "网络共享器" as CFString, nil, nil),
          let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/IPv4" as CFString) as? [String] else { return [] }
    var servers: [String] = []
    for key in keys.sorted() {
        guard let ipv4 = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
              ipv4["InterfaceName"] as? String == device else { continue }
        let dnsKey = String(key.dropLast("IPv4".count)) + "DNS"
        guard let dns = SCDynamicStoreCopyValue(store, dnsKey as CFString) as? [String: Any] else { continue }
        for server in dns["ServerAddresses"] as? [String] ?? [] where validDNSServer(server) && !servers.contains(server) {
            servers.append(server)
        }
    }
    return Array(servers.prefix(2))
}

// Only negotiate the SOCKS method. Credentials and destination traffic are not sent.
func checkSOCKSMethod(port: Int, requiresAuthentication: Bool) -> (CheckLevel, String) {
    guard (1...65535).contains(port) else { return (.attention, "端口应为 1–65535") }
    let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { return (.attention, "无法检查代理端口") }
    defer { Darwin.close(fd) }
    let originalFlags = fcntl(fd, F_GETFL, 0)
    guard originalFlags >= 0, fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK) == 0 else {
        return (.attention, "无法检查代理端口")
    }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = in_port_t(port).bigEndian
    address.sin_addr = in_addr(s_addr: UInt32(INADDR_LOOPBACK).bigEndian)
    let result = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    if result != 0 {
        guard errno == EINPROGRESS || errno == EWOULDBLOCK else { return (.attention, "本机代理端口不可连接") }
        var wait = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard Darwin.poll(&wait, 1, 1000) > 0 else { return (.attention, "本机代理端口无响应") }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else {
            return (.attention, "本机代理端口不可连接")
        }
    }
    guard fcntl(fd, F_SETFL, originalFlags) == 0 else { return (.attention, "无法检查代理端口") }
    var timeout = timeval(tv_sec: 1, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var noSignal: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    let method: UInt8 = requiresAuthentication ? 2 : 0
    let hello: [UInt8] = [5, 1, method]
    let sent = hello.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
    guard sent == hello.count else { return (.attention, "代理握手失败") }
    var reply = [UInt8](repeating: 0, count: 2)
    let received = reply.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress, $0.count, MSG_WAITALL) }
    guard received == 2, reply[0] == 5 else { return (.attention, "端口不是可用的 SOCKS5 代理") }
    guard reply[1] == method else { return (.attention, "代理不支持所选认证方式") }
    return (.good, requiresAuthentication ? "端口已响应，密码将在启动时验证" : "本机 SOCKS5 端口已响应")
}

// Use the same isolated gateway as sharing for a single fixed-name DNS query.
// The check never reads browsing traffic or sends SOCKS credentials.
func checkDNSResponse(server: String, source: String, proxyPort: Int?, gatewayPath: String) -> (CheckLevel, String) {
    guard validDNSServer(server) else { return (.attention, "请输入有效的 IPv4 地址") }
    let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    let task = Process()
    let output = Pipe()
    task.executableURL = URL(fileURLWithPath: gatewayPath)
    task.arguments = proxyPort == nil ? ["direct", source] : ["socks5", String(proxyPort!)]
    task.standardOutput = output
    task.standardError = FileHandle.nullDevice
    var env = ProcessInfo.processInfo.environment
    env["NAPTD_RELAY_TOKEN"] = token
    env["NAPTD_DNS_SERVER"] = server
    env["NAPTD_CONTROLLER_PID"] = String(getpid())
    env.removeValue(forKey: "NAPTD_DNS_SECONDARY")
    env.removeValue(forKey: "NAPTD_PROXY_AUTH_FILE")
    task.environment = env
    do { try task.run() } catch { return (.attention, "DNS 检查无法启动") }
    defer {
        if task.isRunning { task.terminate() }
        task.waitUntilExit()
    }
    let pipeFD = output.fileHandleForReading.fileDescriptor
    var pollFD = pollfd(fd: pipeFD, events: Int16(POLLIN), revents: 0)
    guard Darwin.poll(&pollFD, 1, 3000) > 0 else { return (.attention, "DNS 检查连接超时") }
    var line = [UInt8]()
    while line.count < 96 {
        var byte: UInt8 = 0
        guard Darwin.read(pipeFD, &byte, 1) == 1 else { return (.attention, "DNS 检查无法启动") }
        if byte == 10 { break }
        line.append(byte)
    }
    let pieces = String(decoding: line, as: UTF8.self).split(separator: ":")
    guard pieces.count == 3, pieces[0] == "gateway_ready", let port = UInt16(pieces[2]), port > 0 else {
        return (.attention, "DNS 检查无法启动")
    }
    let fd = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { return (.attention, "DNS 检查无法启动") }
    defer { Darwin.close(fd) }
    var timeout = timeval(tv_sec: 4, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var destination = sockaddr_in()
    destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    destination.sin_family = sa_family_t(AF_INET)
    destination.sin_port = port.bigEndian
    destination.sin_addr = in_addr(s_addr: UInt32(INADDR_LOOPBACK).bigEndian)
    let connected = withUnsafePointer(to: &destination) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { return (.attention, "DNS 检查无法连接") }
    let query: [UInt8] = [0x48, 0x62, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
                          7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1]
    let packet = Array("DNS1".utf8) + Array(token.utf8) + query
    let sent = packet.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
    guard sent == packet.count else { return (.attention, "DNS 请求发送失败") }
    var reply = [UInt8](repeating: 0, count: 4132)
    let count = reply.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress, $0.count, 0) }
    guard count >= 48, Array(reply[0..<36]) == Array("DNS1".utf8) + Array(token.utf8),
          reply[36] == query[0], reply[37] == query[1], reply[38] & 0x80 != 0,
          reply[39] & 0x0f == 0, (reply[42] != 0 || reply[43] != 0) else {
        return (.attention, "DNS 查询未成功，请检查服务器")
    }
    return (.good, "\(server) · 已响应")
}

@MainActor final class HotspotModel: ObservableObject {
    @Published var adapters: [Adapter] = []
    @Published var sourceDevice = ""
    @Published var selectedDevices: Set<String> = []
    @Published var sharingState = "idle"
    @Published var sharingMessage = "请选择用于连接设备的端口。"
    @Published var runningBridge = ""
    @Published var routeMode = "direct"
    @Published var proxyPort = "1082"
    @Published var dnsServer = ""
    @Published var dnsSecondary = ""
    @Published var useAuthentication = false
    @Published var proxyUsername = ""
    @Published var proxyPassword = ""
    @Published var wifiAddress = "未连接"
    @Published var wifiNetwork = "未连接"
    @Published var sharedAddress = "未运行"
    @Published var sharedNetwork = "未运行"
    @Published var clientAddresses = "未发现"
    @Published var otherSharing = false
    @Published var showChecks = true
    @Published var subnetLevel: CheckLevel = .pending
    @Published var subnetDetail = "正在检查"
    @Published var proxyLevel: CheckLevel = .pending
    @Published var proxyDetail = "正在检查"
    @Published var dnsLevel: CheckLevel = .pending
    @Published var dnsDetail = "等待网络"
    private var runtimePath: String?
    private var heartbeat: Timer?
    private var startTime: Date?
    private var infoTimer: Timer?
    private var adaptersRefreshInFlight = false
    private var infoRefreshInFlight = false
    private var proxyProbeGeneration = 0
    private var dnsProbeGeneration = 0
    private var dnsLoadGeneration = 0
    private var dnsLoadedFor = ""
    private var dnsManuallyEdited = false
    private var infoTick = 0
    private var selectedPortAssignments: [String: String] = [:]

    init() {
        signal(SIGPIPE, SIG_IGN)
        refreshAdapters()
        infoTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshAdapters()
                self?.refreshNetworkInfo()
                self?.refreshProxyCheck()
                guard let self else { return }
                self.infoTick += 1
                if self.infoTick % 6 == 0 && self.showChecks { self.refreshDNSCheck(showChecking: false) }
                if self.infoTick % 6 == 0 { self.loadWiFiDNSIfNeeded(force: true) }
            }
        }
        refreshNetworkInfo()
        refreshProxyCheck()
    }

    var canStart: Bool {
        !otherSharing && !sourceDevice.isEmpty && !selectedDevices.isEmpty && !selectedDevices.contains(sourceDevice) && validDNSServer(dnsServer) &&
        (dnsSecondary.isEmpty || validDNSServer(dnsSecondary)) &&
        (routeMode == "direct" || (Int(proxyPort).map { (1...65535).contains($0) } ?? false)) &&
        (!useAuthentication || routeMode == "direct" ||
         ((1...255).contains(proxyUsername.utf8.count) && (1...255).contains(proxyPassword.utf8.count))) &&
        (sharingState == "idle" || sharingState == "stopped" || sharingState == "error")
    }

    var isBusy: Bool { sharingState == "running" || sharingState == "waiting" || sharingState == "starting" || sharingState == "stopping" }
    var wifiSources: [Adapter] { adapters.filter { $0.name == "Wi-Fi" && $0.hasIPv4 } }
    var outputPorts: [Adapter] { adapters.filter { $0.device != sourceDevice && $0.name != "Wi-Fi" } }

    var connectionChecks: [ConnectionCheck] {
        let wifiOK = !sourceDevice.isEmpty && wifiAddress != "未连接" && wifiSources.contains { $0.device == sourceDevice }
        let wifi = ConnectionCheck(name: "Wi-Fi 上游", detail: wifiOK ? "\(sourceDevice) · \(wifiAddress)" : "等待已连接的 Wi-Fi", level: wifiOK ? .good : .attention)
        let selected = adapters.filter { selectedDevices.contains($0.device) }
        let connected = selected.filter(\.connected).count
        let ports: ConnectionCheck
        if selectedDevices.isEmpty {
            ports = ConnectionCheck(name: "共享端口", detail: "请选择连接设备的端口", level: .pending)
        } else if selected.count < selectedDevices.count || connected < selectedDevices.count {
            ports = ConnectionCheck(name: "共享端口", detail: "已选择 \(selectedDevices.count) 个，\(connected) 个已连接", level: .attention)
        } else {
            ports = ConnectionCheck(name: "共享端口", detail: "\(connected) 个所选端口已连接", level: .good)
        }
        let subnet = ConnectionCheck(name: "共享网段", detail: subnetDetail, level: subnetLevel)
        let resources = Bundle.main.resourceURL!
        let binaries = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS")
        let required = [resources.appendingPathComponent("engine.sh"), resources.appendingPathComponent("private_runtime.dylib"),
                        resources.appendingPathComponent("network.desktop.xml"), binaries.appendingPathComponent("prl_naptd"),
                        binaries.appendingPathComponent("mock_dispatcher"), binaries.appendingPathComponent("socks_gateway"),
                        binaries.appendingPathComponent("mobile_identity"), binaries.appendingPathComponent("session_supervisor"),
                        binaries.appendingPathComponent("subnet_guard"), binaries.appendingPathComponent("lease_store"),
                        resources.appendingPathComponent("reconnect_helpers.sh")]
        let ready = required.allSatisfy { FileManager.default.fileExists(atPath: $0.path) }
        let engine = ConnectionCheck(name: "共享组件", detail: ready ? ((sharingState == "running" || sharingState == "waiting") ? "正在运行" : "组件齐全") : "应用组件缺失", level: ready ? .good : .attention)
        let dns = ConnectionCheck(name: "DNS 设置", detail: dnsDetail, level: dnsLevel)
        var items = [wifi, ports, subnet, dns, engine]
        if routeMode == "socks5" { items.append(ConnectionCheck(name: "SOCKS5 代理", detail: proxyDetail, level: proxyLevel)) }
        return items
    }

    var engineScript: String {
        Bundle.main.resourceURL!.appendingPathComponent("engine.sh").path
    }

    func refreshAdapters() {
        guard !adaptersRefreshInFlight else { return }
        adaptersRefreshInFlight = true
        DispatchQueue.global(qos: .userInitiated).async {
            let result = runCommand("/usr/sbin/networksetup", ["-listallhardwareports"])
            var names: [(String, String)] = []
            var currentName = ""
            for line in result.output.components(separatedBy: .newlines) {
                if line.hasPrefix("Hardware Port: ") {
                    currentName = String(line.dropFirst("Hardware Port: ".count))
                } else if line.hasPrefix("Device: ") {
                    let device = String(line.dropFirst("Device: ".count))
                    if device.hasPrefix("en") || device.hasPrefix("ap") || device.hasPrefix("bridge") {
                        if !currentName.hasPrefix("Thunderbolt 1") && !currentName.hasPrefix("Thunderbolt 2") {
                            names.append((currentName, device))
                        }
                    }
                }
            }
            let mobilePorts = discoverMobilePorts()
            for port in mobilePorts.sorted() where !names.contains(where: { $0.1 == port }) {
                names.append(("iPhone USB", port))
            }
            if names.isEmpty {
                let fallback = runCommand("/sbin/ifconfig", ["-l"])
                names = fallback.output.split(whereSeparator: { $0.isWhitespace })
                    .map(String.init).filter { $0.hasPrefix("en") || $0.hasPrefix("ap") }
                    .map { ("网络接口", $0) }
            }
            let found = names.compactMap { name, device -> Adapter? in
                let status = runCommand("/sbin/ifconfig", [device]).output
                let connected = status.contains("status: active")
                let hasIPv4 = status.components(separatedBy: .newlines).contains { $0.trimmingCharacters(in: .whitespaces).hasPrefix("inet ") }
                let mobile = mobilePorts.contains(device) || name.lowercased().contains("iphone") || name.lowercased().contains("ipad")
                if mobile && !mobilePorts.contains(device) { return nil }
                return Adapter(name: mobile ? "iPhone USB" : name, device: device, connected: connected,
                               hasIPv4: hasIPv4, mobile: mobile, bridgeable: !device.hasPrefix("bridge"))
            }
            DispatchQueue.main.async {
                var updated = found
                if self.isBusy {
                    for old in self.adapters where !old.mobile && self.selectedDevices.contains(old.device) && !updated.contains(where: { $0.device == old.device }) {
                        updated.append(Adapter(name: old.name, device: old.device, connected: false, hasIPv4: false,
                                               mobile: old.mobile, bridgeable: old.bridgeable))
                    }
                } else {
                    if !found.contains(where: { $0.device == self.sourceDevice && $0.name == "Wi-Fi" && $0.hasIPv4 }) {
                        self.sourceDevice = found.first(where: { $0.name == "Wi-Fi" && $0.hasIPv4 })?.device ?? ""
                    }
                    self.selectedDevices.formIntersection(Set(found.filter { $0.bridgeable && $0.device != self.sourceDevice }.map(\.device)))
                }
                self.adapters = updated
                self.adaptersRefreshInFlight = false
                self.refreshNetworkInfo()
                self.loadWiFiDNSIfNeeded()
            }
        }
    }

    func loadWiFiDNSIfNeeded(force: Bool = false) {
        guard !isBusy, !dnsManuallyEdited, !sourceDevice.isEmpty,
              force || dnsLoadedFor != sourceDevice || dnsServer.isEmpty else { return }
        let device = sourceDevice
        dnsLoadedFor = device
        dnsLoadGeneration += 1
        let generation = dnsLoadGeneration
        DispatchQueue.global(qos: .utility).async {
            let servers = wifiDNSServers(device)
            DispatchQueue.main.async {
                guard self.dnsLoadGeneration == generation, self.sourceDevice == device,
                      !self.dnsManuallyEdited, !self.isBusy else { return }
                guard self.dnsServer != (servers.first ?? "") || self.dnsSecondary != (servers.count > 1 ? servers[1] : "") else { return }
                self.dnsServer = servers.first ?? ""
                self.dnsSecondary = servers.count > 1 ? servers[1] : ""
                self.refreshDNSCheck()
            }
        }
    }

    func setDNS(_ value: String, secondary: Bool) {
        guard value != (secondary ? dnsSecondary : dnsServer) else { return }
        dnsManuallyEdited = true
        dnsLoadGeneration += 1
        if secondary { dnsSecondary = value } else { dnsServer = value }
        refreshDNSCheck()
    }

    func refreshProxyCheck() {
        proxyProbeGeneration += 1
        let generation = proxyProbeGeneration
        guard routeMode == "socks5" else { proxyLevel = .pending; proxyDetail = "直连模式"; return }
        guard let port = Int(proxyPort), (1...65535).contains(port) else {
            proxyLevel = .attention; proxyDetail = "端口应为 1–65535"; return
        }
        let requiresAuthentication = useAuthentication
        proxyLevel = .pending; proxyDetail = "正在检查本机代理"
        DispatchQueue.global(qos: .utility).async {
            let (level, detail) = checkSOCKSMethod(port: port, requiresAuthentication: requiresAuthentication)
            DispatchQueue.main.async {
                guard self.proxyProbeGeneration == generation else { return }
                self.proxyLevel = level; self.proxyDetail = detail
            }
        }
    }

    func refreshDNSCheck(showChecking: Bool = true) {
        dnsProbeGeneration += 1
        let generation = dnsProbeGeneration
        guard validDNSServer(dnsServer), dnsSecondary.isEmpty || validDNSServer(dnsSecondary) else {
            dnsLevel = .attention; dnsDetail = "请填写有效的首选 DNS，备用 DNS 可留空"; return
        }
        guard !sourceDevice.isEmpty else { dnsLevel = .pending; dnsDetail = "等待已连接的 Wi-Fi"; return }
        if routeMode == "socks5" && useAuthentication {
            dnsLevel = .good; dnsDetail = "地址格式有效；认证代理启动时验证"; return
        }
        let selectedProxy: Int?
        if routeMode == "socks5" {
            guard let port = Int(proxyPort), (1...65535).contains(port) else {
                dnsLevel = .attention; dnsDetail = "请先设置有效的代理端口"; return
            }
            selectedProxy = port
        } else { selectedProxy = nil }
        if showChecking { dnsLevel = .pending; dnsDetail = "正在检查 DNS" }
        let dns = dnsServer
        let backup = dnsSecondary
        let source = sourceDevice
        let gatewayPath = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/socks_gateway").path
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self, self.dnsProbeGeneration == generation else { return }
            DispatchQueue.global(qos: .utility).async {
                let primaryResult = checkDNSResponse(server: dns, source: source, proxyPort: selectedProxy, gatewayPath: gatewayPath)
                var level = primaryResult.0
                var detail = primaryResult.1
                if !backup.isEmpty && backup != dns {
                    let backupResult = checkDNSResponse(server: backup, source: source, proxyPort: selectedProxy, gatewayPath: gatewayPath)
                    switch (primaryResult.0, backupResult.0) {
                    case (.good, .good): level = .good; detail = "首选和备用 DNS 均已响应"
                    case (.good, _): level = .attention; detail = "首选 DNS 已响应，备用未响应"
                    case (_, .good): level = .attention; detail = "首选 DNS 未响应，备用已响应"
                    default: level = .attention; detail = "首选和备用 DNS 均未响应"
                    }
                }
                DispatchQueue.main.async {
                    guard self.dnsProbeGeneration == generation else { return }
                    self.dnsLevel = level; self.dnsDetail = detail
                }
            }
        }
    }

    func refreshNetworkInfo() {
        guard !infoRefreshInFlight else { return }
        infoRefreshInFlight = true
        let source = sourceDevice
        let ownPath = runtimePath
        DispatchQueue.global(qos: .utility).async {
            let wifi = ipv4Details(source)
            let dirs = (try? FileManager.default.contentsOfDirectory(atPath: "/private/tmp")) ?? []
            let candidates = dirs.filter { $0.hasPrefix("networksharer.") || $0.hasPrefix("naptd-hotspot.") }.map { "/private/tmp/" + $0 }
            let running = candidates.compactMap { path -> (String, [String: String])? in
                let state = stateValues(path)
                guard sessionPossiblyActive(state, statePath: path + "/state") else { return nil }
                return (path, state)
            }
            let other = running.contains { $0.0 != ownPath }
            let active = running.first { $0.0 == ownPath }
            let bridge = active?.1["bridge"] ?? ""
            let shared = ipv4Details(bridge)
            let reportedClients = active?.1["clients"] ?? ""
            let clients = reportedClients.isEmpty ? observedClients(bridge) : reportedClients.replacingOccurrences(of: ",", with: "、")
            let subnetGuard = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/subnet_guard").path
            let interfaces = runCommand(subnetGuard, [])
            let routes = runCommand("/usr/sbin/netstat", ["-rn", "-f", "inet"])
            let hasAddressConflict = interfaces.status == 1
            let hasRouteConflict = routes.output.components(separatedBy: .newlines).contains {
                $0.split(whereSeparator: { $0.isWhitespace }).first?.hasPrefix("172.30.77") == true
            }
            let subnet: (CheckLevel, String)
            if active?.0 == ownPath && (active?.1["state"] == "running" || active?.1["state"] == "waiting") {
                subnet = (.good, "172.30.77.0/24 正由本应用使用")
            } else if other || hasAddressConflict || hasRouteConflict {
                subnet = (.attention, "172.30.77.0/24 已被占用")
            } else if interfaces.status != 0 || routes.status != 0 || !routes.output.contains("Destination") {
                subnet = (.pending, "启动时会检查网段是否冲突")
            } else {
                subnet = (.good, "172.30.77.0/24 未发现冲突")
            }
            DispatchQueue.main.async {
                self.infoRefreshInFlight = false
                guard self.runtimePath == ownPath && self.sourceDevice == source else {
                    self.refreshNetworkInfo(); return
                }
                self.wifiAddress = wifi?.address ?? "未连接"
                self.wifiNetwork = wifi?.network ?? "未连接"
                self.sharedAddress = shared?.address ?? (active == nil ? "未运行" : "正在获取")
                self.sharedNetwork = shared?.network ?? (active == nil ? "未运行" : "正在获取")
                self.clientAddresses = clients
                self.otherSharing = other
                self.subnetLevel = subnet.0
                self.subnetDetail = subnet.1
            }
        }
    }

    func startSharing() {
        guard canStart else { return }
        sharingState = "starting"
        sharingMessage = "等待管理员授权并检查共享端口…"
        let selectedMode = routeMode
        let port = selectedMode == "socks5" ? String(Int(proxyPort) ?? 0) : "0"
        let user = selectedMode == "socks5" && useAuthentication ? Array(proxyUsername.utf8) : []
        let password = selectedMode == "socks5" && useAuthentication ? Array(proxyPassword.utf8) : []
        let auth = [UInt8(user.count)] + user + [UInt8(password.count)] + password
        let selected = selectedDevices.sorted()
        selectedPortAssignments = Dictionary(uniqueKeysWithValues: selected.map { ($0, $0) })
        let specs = selected.map { device in
            adapters.first(where: { $0.device == device })?.mobile == true ? device + "@mobile" : device
        }
        let arguments = [engineScript, "launch", String(getuid()), String(getpid()), sourceDevice, selectedMode, port, dnsServer,
                         dnsSecondary.isEmpty ? "-" : dnsSecondary] + specs
        let command = "/bin/bash " + arguments.map(shellQuote).joined(separator: " ")
        let script = "do shell script " + appleScriptQuote(command) + " with administrator privileges"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = runCommand("/usr/bin/osascript", ["-e", script])
            let path = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                guard result.status == 0, path.hasPrefix("/private/tmp/networksharer."),
                      !path.dropFirst("/private/tmp/networksharer.".count).contains("/") else {
                    self.sharingState = "error"
                    self.sharingMessage = result.error.isEmpty ? "启动未完成。" : String(result.error.prefix(220))
                    return
                }
                self.runtimePath = path
                self.startTime = Date()
                guard self.writeConfiguration(auth) else {
                    _ = self.sendControl("STOP")
                    self.sharingState = "error"; self.sharingMessage = "无法安全写入连接配置。"
                    self.runtimePath = nil; return
                }
                self.proxyPassword = ""
                _ = self.sendControl("READY")
                self.startHeartbeat()
            }
        }
    }

    private func writeConfiguration(_ bytes: [UInt8]) -> Bool {
        guard let runtimePath else { return false }
        let path = runtimePath + "/auth"
        let fd = path.withCString { Darwin.open($0, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW) }
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        return bytes.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return false }
            return Darwin.write(fd, base, raw.count) == raw.count
        }
    }

    private func sendControl(_ value: String) -> Bool {
        guard let runtimePath else { return false }
        let path = runtimePath + "/control"
        let fd = path.withCString { Darwin.open($0, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW) }
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        let data = Array((value + "\n").utf8)
        return data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return false }
            return Darwin.write(fd, base, raw.count) == raw.count
        }
    }

    private func startHeartbeat() {
        heartbeat?.invalidate()
        updateState()
        heartbeat = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.updateState() }
        }
    }

    private func updateState() {
        guard let runtimePath else { return }
        let values = stateValues(runtimePath)
        guard !values.isEmpty else {
            if sharingState == "starting" { sharingState = "error"; sharingMessage = "共享组件已停止，请重试。" }
            else { sharingState = "stopped"; sharingMessage = "共享已停止。" }
            stopHeartbeat()
            return
        }
        if let mapping = values["portmap"] {
            for part in mapping.split(separator: ",") {
                let pair = part.split(separator: ":", maxSplits: 1).map(String.init)
                guard pair.count == 2, pair[1] != "-", let previous = selectedPortAssignments[pair[0]], previous != pair[1] else { continue }
                selectedDevices.remove(previous)
                selectedDevices.insert(pair[1])
                selectedPortAssignments[pair[0]] = pair[1]
            }
        }
        if let state = values["state"] {
            if sharingState != "stopping" || state == "stopped" || state == "error" { sharingState = state }
            if let message = values["message"], sharingState != "stopping" { sharingMessage = message }
            runningBridge = values["bridge"] ?? ""
            if state == "stopped" || state == "error" { stopHeartbeat() }
        }
        refreshNetworkInfo()
        if sharingState == "starting", let startTime, Date().timeIntervalSince(startTime) > 35 {
            _ = sendControl("STOP")
            sharingState = "error"; sharingMessage = "启动超时，已请求清理临时网络。"; stopHeartbeat()
        }
    }

    private func stopHeartbeat() {
        heartbeat?.invalidate(); heartbeat = nil
        runtimePath = nil; startTime = nil
        loadWiFiDNSIfNeeded(force: true)
    }

    func stopSharing() {
        guard runtimePath != nil else { return }
        sharingState = "stopping"; sharingMessage = "正在停止并恢复共享端口…"
        if !sendControl("STOP") { sharingMessage = "等待后台组件退出…" }
    }

    func shutdown() {
        _ = sendControl("STOP")
    }


}

struct StatusDot: View {
    let color: Color
    var body: some View { Circle().fill(color).frame(width: 8, height: 8) }
}

struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 16) { content }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(22)
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.primary.opacity(0.08)))
    }
}

struct AddressRow: View {
    let title: String
    let value: String
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).foregroundStyle(.secondary)
            Spacer(minLength: 20)
            Text(value).textSelection(.enabled).multilineTextAlignment(.trailing)
        }.font(.system(size: 12))
    }
}

struct ConnectionCheckRow: View {
    let check: ConnectionCheck
    var color: Color {
        switch check.level {
        case .good: return .green
        case .attention: return .orange
        case .pending: return .secondary
        }
    }
    var symbol: String {
        switch check.level {
        case .good: return "checkmark.circle.fill"
        case .attention: return "exclamationmark.circle.fill"
        case .pending: return "circle.dashed"
        }
    }
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 9) {
            Image(systemName: symbol).foregroundStyle(color).frame(width: 16)
            Text(check.name).font(.system(size: 12, weight: .medium))
            Spacer(minLength: 20)
            Text(check.detail).font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.trailing)
        }.padding(.vertical, 3)
    }
}

struct ContentView: View {
    @ObservedObject var model: HotspotModel
    var stateLabel: String {
        switch model.sharingState {
        case "running": return "共享端口已接入"
        case "waiting": return "等待设备重新连接"
        case "starting": return "正在启动"
        case "stopping": return "正在停止"
        case "error": return "需要处理"
        default: return "已关闭"
        }
    }
    var stateColor: Color {
        switch model.sharingState {
        case "running": return .green
        case "starting", "waiting", "stopping": return .orange
        case "error": return .red
        default: return .secondary
        }
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 15) {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12).fill(Color.accentColor.gradient).frame(width: 44, height: 44)
                        Image(systemName: "network").font(.system(size: 21, weight: .semibold)).foregroundStyle(.white)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 7) {
                            Text("互联网共享").font(.system(size: 18, weight: .semibold))
                            StatusDot(color: stateColor)
                            Text(stateLabel).font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                        Text("将 Mac 的网络共享给其他设备").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("互联网共享", isOn: Binding(
                        get: { model.isBusy },
                        set: { enabled in enabled ? model.startSharing() : model.stopSharing() }
                    ))
                    .labelsHidden().toggleStyle(.switch)
                    .disabled(model.sharingState == "starting" || model.sharingState == "stopping" || (!model.isBusy && !model.canStart))
                }
                .padding(16).background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 14))

                HStack {
                    Text("共享以下来源的连接").font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Picker("上游网络", selection: $model.sourceDevice) {
                        if model.wifiSources.isEmpty { Text("未检测到已连接的 Wi-Fi").tag("") }
                        ForEach(model.wifiSources) { adapter in Text("Wi-Fi  ·  \(adapter.device)").tag(adapter.device) }
                    }.labelsHidden().frame(maxWidth: 250).disabled(model.isBusy || model.wifiSources.isEmpty)
                        .onChange(of: model.sourceDevice) { model.refreshNetworkInfo(); model.loadWiFiDNSIfNeeded(); model.refreshDNSCheck() }
                }
                .padding(16).background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 14))

                VStack(alignment: .leading, spacing: 12) {
                    Text("连接方式").font(.system(size: 14, weight: .semibold))
                    Picker("连接方式", selection: $model.routeMode) {
                        Text("Wi-Fi 直连").tag("direct")
                        Text("SOCKS5 代理").tag("socks5")
                    }.pickerStyle(.segmented).disabled(model.isBusy)
                        .onChange(of: model.routeMode) { model.refreshProxyCheck(); model.refreshDNSCheck() }
                    if model.routeMode == "direct" {
                        Text("共享流量绑定所选 Wi-Fi 出口，绕过系统 VPN 和系统代理；连接失败时不会回退。网络本身仍可能进行透明转发。")
                            .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    } else {
                        HStack {
                            Text("代理地址").font(.system(size: 12)).foregroundStyle(.secondary)
                            Text("127.0.0.1 :").font(.system(size: 13, design: .monospaced))
                            TextField("1082", text: $model.proxyPort).frame(width: 80).disabled(model.isBusy)
                                .onChange(of: model.proxyPort) { model.refreshProxyCheck(); model.refreshDNSCheck() }
                            Toggle("需要认证", isOn: $model.useAuthentication).disabled(model.isBusy)
                                .onChange(of: model.useAuthentication) { model.refreshProxyCheck(); model.refreshDNSCheck() }
                            Spacer()
                        }
                        if model.useAuthentication {
                            HStack {
                                TextField("用户名", text: $model.proxyUsername)
                                SecureField("密码", text: $model.proxyPassword)
                            }.disabled(model.isBusy)
                            Text("用户名与密码各限 1–255 个 UTF-8 字节；密码启动后清空，不保存。")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Text("TCP 和 DNS 经过指定的 SOCKS5 端口；其他 UDP 暂不支持并会阻断。代理软件自身的分流规则仍然生效。")
                            .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("DNS 服务器").font(.system(size: 12)).foregroundStyle(.secondary)
                            Text("默认使用当前 Wi-Fi，可手动修改").font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        HStack {
                            TextField("首选 IPv4", text: Binding(get: { model.dnsServer }, set: { model.setDNS($0, secondary: false) }))
                            TextField("备用 IPv4（可留空）", text: Binding(get: { model.dnsSecondary }, set: { model.setDNS($0, secondary: true) }))
                        }.disabled(model.isBusy)
                    }
                }
                .padding(16).background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 14))

                VStack(alignment: .leading, spacing: 8) {
                    Text("网络地址").font(.system(size: 14, weight: .semibold))
                    AddressRow(title: "本机 Wi-Fi IPv4", value: model.wifiAddress)
                    AddressRow(title: "本机 Wi-Fi 网段", value: model.wifiNetwork)
                    Divider()
                    AddressRow(title: "共享网段", value: model.sharedNetwork)
                    AddressRow(title: "Mac 共享接口 IPv4", value: model.sharedAddress)
                    AddressRow(title: "共享网关 / DNS", value: model.sharedNetwork == "172.30.77.0/24" ? "172.30.77.1" : "未运行")
                    AddressRow(title: "已发现设备 IPv4", value: model.clientAddresses)
                    Text("设备地址根据网络邻居记录显示，可能有延迟。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                .padding(16).background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 14))

                VStack(alignment: .leading, spacing: 0) {
                    HStack {
                        Text("使用以下端口共享给设备").font(.system(size: 14, weight: .semibold))
                        Spacer()
                    }.padding(.horizontal, 16).padding(.vertical, 13)
                    Divider()
                    if model.outputPorts.isEmpty {
                        Text("没有可用端口，请连接设备；列表会自动更新。")
                            .font(.system(size: 13)).foregroundStyle(.secondary).padding(16)
                    }
                    ForEach(model.outputPorts) { adapter in
                        HStack(spacing: 12) {
                            Image(systemName: adapter.mobile ? "iphone" : "cable.connector")
                                .foregroundStyle(.secondary).frame(width: 20)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(adapter.displayTitle).font(.system(size: 13, weight: .medium))
                                Text(!adapter.bridgeable ? "系统网桥暂不支持" : (adapter.connected ? "已连接" : "未检测到连接"))
                                    .font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Toggle(adapter.name + " " + adapter.device, isOn: Binding(
                                get: { model.selectedDevices.contains(adapter.device) },
                                set: { enabled in
                                    if enabled { model.selectedDevices.insert(adapter.device) }
                                    else { model.selectedDevices.remove(adapter.device) }
                                }
                            ))
                            .labelsHidden().toggleStyle(.switch).controlSize(.small)
                            .disabled(model.isBusy || !adapter.bridgeable)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 9)
                        if adapter.id != model.outputPorts.last?.id { Divider().padding(.leading, 48) }
                    }
                }
                .background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 14))

                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "info.circle").foregroundStyle(.secondary)
                    Text("支持 IPv4 设备；DNS 使用上面指定的服务器，并按所选连接方式转发。")
                        .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if model.otherSharing {
                    Text("检测到已有共享正在运行。请先在旧版应用中关闭共享，再启动本版本。")
                        .font(.system(size: 12, weight: .medium)).foregroundStyle(.orange)
                }
                Text(model.sharingMessage).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

                DisclosureGroup("本地连接检查", isExpanded: $model.showChecks) {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(model.connectionChecks) { check in
                            ConnectionCheckRow(check: check)
                        }
                        Text("自动检查本机配置；不代表所有网站或节点均可连接。")
                            .font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 5)
                    }.padding(.top, 10)
                }
                .font(.system(size: 13, weight: .medium)).padding(14)
                .background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .padding(24)
        }
        .frame(minWidth: 700, minHeight: 620)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var onQuit: (() -> Void)?
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { onQuit?() }
}

@main struct HotspotLabApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = HotspotModel()
    var body: some Scene {
        WindowGroup {
            ContentView(model: model).onAppear { delegate.onQuit = { model.shutdown() } }
        }
        .windowResizability(.contentMinSize)
    }
}

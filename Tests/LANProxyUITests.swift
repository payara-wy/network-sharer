import AppKit
import Foundation
import SwiftUI

final class MemoryCredentialStore: LANCredentialStore {
    var record: LANCredentials?
    var failure = false
    var writes = 0
    func load() throws -> LANCredentials? {
        if failure { throw LANCredentialError.invalidRecord }
        return record
    }
    func save(_ credentials: LANCredentials) throws {
        if failure { throw LANCredentialError.invalidRecord }
        record = credentials; writes += 1
    }
}

@main struct LANUITests {
    @MainActor static func main() throws {
        let store = MemoryCredentialStore()
        let model = HotspotModel(credentialStore: store, observesSystem: false)
        assert(model.lanProxyUsername == "Mac")
        assert(model.lanProxyPassword.isEmpty)
        assert(!model.lanProxyEnabled && model.sharingState == "idle")
        model.sourceDevice = "en0"; model.wifiAddress = "192.168.1.23"
        model.wifiNetwork = "192.168.1.0/24"; model.dnsServer = "192.168.1.1"
        model.lanProxyEnabled = true
        model.lanProxyPassword = "demo-only-secret"
        assert(model.canStart)
        let running = ["state":"running", "lan_ready":"1", "lan_port":"1080", "bridge":""]
        model.applySessionState(running)
        assert(model.lanCheck.level == .good)
        assert(model.lanProxyPassword == "demo-only-secret")
        // Reproduce the old bug: a cleared editor must not downgrade live state.
        model.lanProxyPassword = ""
        assert(!model.lanProxyValid && model.lanCheck.level == .good)
        model.applySessionState(["state":"waiting", "lan_ready":"1", "lan_port":"1080"])
        assert(model.lanCheck.level == .good)
        model.wifiAddress = "未连接"
        assert(model.lanCheck.level == .attention)
        model.wifiAddress = "192.168.1.23"
        for state in ["starting", "stopping", "error", "stopped"] {
            model.sharingState = state
            assert(model.lanCheck.level != .good)
        }
        model.applySessionState(["state":"stopped", "lan_ready":"1", "lan_port":"1080"])
        assert(!model.lanProxyReady && model.lanProxyAddress.isEmpty)
        assert(store.writes == 0, "State polling alone must not save an unsubmitted form")
        let launchStore = MemoryCredentialStore()
        let launchModel = HotspotModel(credentialStore: launchStore, observesSystem: false)
        launchModel.lanProxyEnabled = true
        launchModel.lanProxyPassword = "synthetic-launch"
        launchModel.prepareSharingState()
        assert(launchStore.writes == 0 && launchModel.pendingLANCredentials != nil)
        launchModel.applySessionState(["state":"starting", "lan_ready":"0"])
        assert(launchStore.writes == 0)
        launchModel.applySessionState(running)
        assert(launchStore.writes == 1 && launchModel.pendingLANCredentials == nil)
        launchModel.applySessionState(running)
        assert(launchStore.writes == 1)
        launchModel.applySessionState(["state":"stopped"])
        launchModel.lanProxyPassword = "changed-but-failed"
        launchModel.prepareSharingState()
        launchModel.applySessionState(["state":"error", "lan_ready":"1", "lan_port":"1080"])
        assert(launchStore.writes == 1 && launchModel.pendingLANCredentials == nil)

        let credentials = LANCredentials(username: "My Mac 用户", secret: "a-unique-test-value")
        model.rememberLANCredentials(credentials)
        assert(store.record == credentials && store.writes == 1)
        model.rememberLANCredentials(credentials)
        assert(store.writes == 1, "Do not write every heartbeat")
        let restarted = HotspotModel(credentialStore: store, observesSystem: false)
        assert(restarted.lanProxyUsername == credentials.username && restarted.lanProxyPassword == credentials.secret)
        assert(!restarted.lanProxyEnabled)
        store.failure = true
        model.rememberLANCredentials(LANCredentials(username: "changed", secret: "not-saved"))
        assert(model.credentialWarning && store.record == credentials)
        let locked = HotspotModel(credentialStore: store, observesSystem: false)
        assert(locked.lanProxyUsername == "Mac" && locked.lanProxyPassword.isEmpty && locked.credentialWarning)

        assert(!LANCredentials(username: "", secret: "a").isValid)
        assert(!LANCredentials(username: "a", secret: "").isValid)
        assert(LANCredentials(username: String(repeating: "a", count: 255), secret: "b").isValid)
        assert(!LANCredentials(username: String(repeating: "a", count: 256), secret: "b").isValid)
        assert(!LANCredentials(username: "a", secret: String(repeating: "中", count: 86)).isValid)
        assert(activeDNSAddress(primary: .good, secondary: .good, primaryAddress: "1.1.1.1", secondaryAddress: "8.8.8.8") == "1.1.1.1")
        assert(activeDNSAddress(primary: .attention, secondary: .good, primaryAddress: "1.1.1.1", secondaryAddress: "8.8.8.8") == "8.8.8.8")
        assert(activeDNSAddress(primary: .attention, secondary: .attention, primaryAddress: "1.1.1.1", secondaryAddress: "8.8.8.8").isEmpty)
        assert(lanConfigurationIssue(port: "1080", credentials: credentials, upstreamPort: "01080") != nil)
        for port in ["0", "65536", "bad"] {
            assert(lanConfigurationIssue(port: port, credentials: credentials, upstreamPort: nil) != nil)
        }
        print("PASS: defaults, state transitions, password masking semantics, restoration, failure handling, UTF-8 boundaries")

        if CommandLine.arguments.count > 1 {
            try testPreferences()
        }
        if CommandLine.arguments.count > 2 {
            let app = NSApplication.shared
            app.setActivationPolicy(.prohibited)
            store.failure = false
            let preview = HotspotModel(credentialStore: MemoryCredentialStore(), observesSystem: false)
            preview.adapters = [Adapter(name: "Wi-Fi", device: "en0", connected: true, hasIPv4: true, mobile: false, bridgeable: false),
                                Adapter(name: "iPhone USB", device: "en7", connected: true, hasIPv4: false, mobile: true, bridgeable: true)]
            preview.sourceDevice = "en0"; preview.wifiAddress = "192.168.1.23"; preview.wifiNetwork = "192.168.1.0/24"
            preview.dnsServer = "192.168.1.1"; preview.dnsSecondary = "8.8.8.8"
            preview.dnsDetail = "首选 DNS 未响应，备用已响应"; preview.dnsLevel = .attention
            preview.dnsPrimaryLevel = .attention; preview.dnsSecondaryLevel = .good
            preview.dnsActiveAddress = "8.8.8.8"
            preview.subnetDetail = "仅代理模式，不使用共享网段"
            preview.lanProxyEnabled = true; preview.lanProxyPassword = "demo-only-secret"
            preview.credentialNotice = "账号已记住"
            preview.applySessionState(running)
            preview.showChecks = true
            for (name, scheme, appearance, width, state, mode) in [
                ("light", ColorScheme.light, NSAppearance.Name.aqua, 720.0, "running", "direct"),
                ("dark", ColorScheme.dark, NSAppearance.Name.darkAqua, 720.0, "running", "direct"),
                ("narrow", ColorScheme.light, NSAppearance.Name.aqua, 640.0, "idle", "direct"),
                ("error", ColorScheme.light, NSAppearance.Name.aqua, 640.0, "error", "direct"),
                ("socks5", ColorScheme.light, NSAppearance.Name.aqua, 720.0, "idle", "socks5")
            ] {
                preview.routeMode = mode
                preview.sharingState = state
                preview.sharingMessage = state == "error" ? "代理端口已被占用，请更换端口后重试。" : ""
                let view = ContentView(model: preview, showDNS: true).environment(\.colorScheme, scheme)
                let host = NSHostingView(rootView: view)
                host.frame = NSRect(x: 0, y: 0, width: width, height: 1250)
                let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
                window.appearance = NSAppearance(named: appearance)
                window.contentView = host
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(0.3))
                host.layoutSubtreeIfNeeded()
                guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else {
                    fatalError("Unable to allocate native view snapshot")
                }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                guard let data = bitmap.representation(using: .png, properties: [:]) else {
                    fatalError("Unable to encode native view snapshot")
                }
                try data.write(to: URL(fileURLWithPath: CommandLine.arguments[2] + "/ui-" + name + ".png"))
                window.contentView = nil
            }
            print("PASS: captured AppKit-hosted light and dark views with synthetic data")
        }
    }

    static func testPreferences() throws {
        // Volatile defaults never write into the user's preference domains.
        final class TestDefaults: UserDefaults {
            var values: [String: Any] = [:]
            override func object(forKey key: String) -> Any? { values[key] }
            override func set(_ value: Any?, forKey key: String) { values[key] = value }
        }
        let defaults = TestDefaults()
        let store = PreferencesLANCredentialStore(defaults: defaults)
        let empty = try store.load(); assert(empty == nil)
        let first = LANCredentials(username: "Mac", secret: "test-only")
        try store.save(first)
        let restored = try PreferencesLANCredentialStore(defaults: defaults).load()
        assert(restored == first)
        let changed = LANCredentials(username: "Desktop", secret: "updated")
        try store.save(changed)
        let updated = try store.load(); assert(updated == changed)
        defaults.set(["username": "missing-secret"], forKey: PreferencesLANCredentialStore.key)
        do { _ = try store.load(); assertionFailure("invalid record accepted") }
        catch LANCredentialError.invalidRecord { }
        print("PASS: preferences write, restore, update and invalid record; no external storage")
    }
}

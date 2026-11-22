// Regression for the confirmed DNS display issue; no network probes.
import Foundation

struct AuditEmptyStore: LANCredentialStore {
    func load() throws -> LANCredentials? { nil }
    func save(_ value: LANCredentials) throws { }
}

@main struct DNSStatusAudit {
    @MainActor static func main() {
        let model=HotspotModel(credentialStore: AuditEmptyStore(), observesSystem: false)
        model.sourceDevice="en0"
        model.wifiAddress="192.0.2.10"
        model.routeMode="socks5"
        model.useAuthentication=true
        model.dnsServer="203.0.113.1"
        model.dnsSecondary="203.0.113.2"
        model.refreshDNSCheck()
        // No probe was possible, so no resolver should be claimed as active.
        assert(model.dnsPrimaryLevel == .pending && model.dnsSecondaryLevel == .pending)
        assert(model.dnsActiveAddress.isEmpty)
        assert(model.dnsSummary == "启动时验证")
        print("PASS: unprobed DNS remains unselected in authenticated mode")
    }
}

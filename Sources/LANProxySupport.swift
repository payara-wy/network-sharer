import Foundation

struct LANCredentials: Codable, Equatable {
    var username: String
    var secret: String
    static let initial = LANCredentials(username: "Mac", secret: "")

    var isValid: Bool {
        (1...255).contains(username.utf8.count) && (1...255).contains(secret.utf8.count)
    }
}

protocol LANCredentialStore {
    func load() throws -> LANCredentials?
    func save(_ credentials: LANCredentials) throws
}

enum LANCredentialError: Error {
    case invalidRecord
}

/// Ordinary application preferences, intentionally unencrypted. No custom
/// credential path or keychain. The UI mask is visual only.
struct PreferencesLANCredentialStore: LANCredentialStore {
    static let key = "lanClientCredentials"
    var defaults: UserDefaults = .standard

    func load() throws -> LANCredentials? {
        guard let record = defaults.object(forKey: Self.key) else { return nil }
        guard let values = record as? [String: String],
              let username = values["username"], let secret = values["secret"] else {
            throw LANCredentialError.invalidRecord
        }
        let credentials = LANCredentials(username: username, secret: secret)
        guard credentials.isValid else { throw LANCredentialError.invalidRecord }
        return credentials
    }

    func save(_ credentials: LANCredentials) throws {
        guard credentials.isValid else { throw LANCredentialError.invalidRecord }
        defaults.set(["username": credentials.username, "secret": credentials.secret], forKey: Self.key)
    }
}

func lanConfigurationIssue(port: String, credentials: LANCredentials, upstreamPort: String?) -> String? {
    guard let number = Int(port), (1...65535).contains(number) else { return "端口需为 1–65535" }
    if let upstreamPort, Int(upstreamPort) == number { return "监听端口不能与上游代理端口相同" }
    if credentials.username.isEmpty { return "请输入用户名" }
    if credentials.secret.isEmpty { return "请输入密码" }
    if !credentials.isValid { return "用户名和密码各限 1–255 个 UTF-8 字节" }
    return nil
}

/// Runtime state must never be inferred from an editable password field.
func lanConnectionCheck(state: String, ready: Bool, address: String, port: String,
                        configurationIssue: String?) -> ConnectionCheck {
    let detail: String
    let level: CheckLevel
    switch state {
    case "stopping": detail = "正在停止"; level = .pending
    case "error": detail = "代理已停止，请重新开启"; level = .attention
    case "starting": detail = "正在启动"; level = .pending
    case "running", "waiting":
        if address.isEmpty || address == "未连接" {
            detail = "Wi-Fi 已断开"; level = .attention
        } else if ready {
            detail = "已就绪 · \(address):\(port)"; level = .good
        } else {
            detail = "代理未就绪"; level = .attention
        }
    default:
        if let configurationIssue { detail = configurationIssue; level = .attention }
        else { detail = "等待开启共享"; level = .pending }
    }
    return ConnectionCheck(name: "局域网隧道", detail: detail, level: level)
}

/// The DNS actually answering right now: primary first, then backup.
func activeDNSAddress(primary: CheckLevel, secondary: CheckLevel,
                      primaryAddress: String, secondaryAddress: String) -> String {
    if primary == .good { return primaryAddress }
    if secondary == .good { return secondaryAddress }
    return ""
}

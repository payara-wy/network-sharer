import CoreFoundation
import CryptoKit
import Foundation
import IOKit

// Emit interface and a one-way device identifier; never print the USB serial.
func property(_ entry: io_registry_entry_t, _ key: String) -> String? {
    IORegistryEntryCreateCFProperty(entry, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String
}

var iterator: io_iterator_t = 0
guard let matching = IOServiceMatching("IONetworkInterface"),
      IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) == KERN_SUCCESS else { exit(1) }
defer { IOObjectRelease(iterator) }
var lines: [String] = []
let salt = ProcessInfo.processInfo.environment["NAPTD_DEVICE_SALT"] ?? ""
let portsOnly = CommandLine.arguments.dropFirst().contains("--ports")
while true {
    let interface = IOIteratorNext(iterator)
    if interface == 0 { break }
    defer { IOObjectRelease(interface) }
    guard let bsd = property(interface, "BSD Name"),
          bsd.range(of: #"^(en|ap)[0-9]+$"#, options: .regularExpression) != nil else { continue }
    var entry = interface
    var mustRelease = false
    var foundProduct = false
    var serial: String?
    for _ in 0..<20 {
        let product = (property(entry, "USB Product Name") ?? property(entry, "kUSBProductString") ?? "").lowercased()
        if product.contains("iphone") || product.contains("ipad") {
            foundProduct = true
            serial = property(entry, "USB Serial Number") ?? property(entry, "kUSBSerialNumberString")
            if serial?.isEmpty == false { break }
        }
        var parent: io_registry_entry_t = 0
        let result = IORegistryEntryGetParentEntry(entry, kIOServicePlane, &parent)
        if mustRelease { IOObjectRelease(entry); mustRelease = false }
        guard result == KERN_SUCCESS else { break }
        entry = parent
        mustRelease = true
    }
    if mustRelease { IOObjectRelease(entry) }
    if foundProduct && portsOnly {
        lines.append(bsd)
    } else if foundProduct, let serial, !serial.isEmpty {
        let digest = SHA256.hash(data: Data((salt + "\u{0}" + serial).utf8)).map { String(format: "%02x", $0) }.joined()
        lines.append("\(bsd) \(digest)")
    }
}
for line in lines.sorted() { print(line) }

import Foundation

nonisolated struct TrustedNetwork: Codable, Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var macFingerprint: String
    var androidFingerprint: String
    var subnet: String
    var gateway: String
    var revision: Int64
    var editor: String
    var deleted: Bool

    var isValid: Bool {
        UUID(uuidString: id) != nil && !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && name.utf16.count <= 80 &&
        [macFingerprint, androidFingerprint].allSatisfy { $0.count == 64 && $0.allSatisfy { $0.isHexDigit } } &&
        Self.ipv4(gateway) != nil && Self.validSubnet(subnet) && revision > 0 && revision < Int64.max / 2 && ["mac", "android"].contains(editor)
    }

    static func merge(_ existing: TrustedNetwork?, _ incoming: TrustedNetwork) -> TrustedNetwork {
        guard let existing else { return incoming }
        guard existing.id == incoming.id, existing.macFingerprint == incoming.macFingerprint,
              existing.androidFingerprint == incoming.androidFingerprint, existing.subnet == incoming.subnet,
              existing.gateway == incoming.gateway else { return existing }
        // A deletion cannot be resurrected by an offline rename. Re-adding creates a new UUID.
        if existing.deleted != incoming.deleted { return existing.deleted ? existing : incoming }
        if existing.revision != incoming.revision { return existing.revision > incoming.revision ? existing : incoming }
        return existing.editor >= incoming.editor ? existing : incoming
    }

    static func ipv4(_ address: String) -> UInt32? {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }), let octet = UInt8(part) else { return nil }
            value = (value << 8) | UInt32(octet)
        }
        return value
    }

    static func subnet(address: String, mask: String) -> String? {
        guard let ip = ipv4(address), let mask = ipv4(mask), mask != 0,
              (~mask &+ 1) & ~mask == 0 else { return nil }
        let network = ip & mask
        return "\((network >> 24) & 255).\((network >> 16) & 255).\((network >> 8) & 255).\(network & 255)/\(mask.nonzeroBitCount)"
    }

    static func validSubnet(_ subnet: String) -> Bool {
        let parts = subnet.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), (1...32).contains(prefix), let ip = ipv4(String(parts[0])) else { return false }
        let mask = UInt32.max << (32 - prefix)
        let canonical = "\((ip >> 24) & 255).\((ip >> 16) & 255).\((ip >> 8) & 255).\(ip & 255)/\(prefix)"
        return ip & mask == ip && canonical == subnet
    }

    static func contains(_ address: String, subnet: String) -> Bool {
        let parts = subnet.split(separator: "/")
        guard validSubnet(subnet), let ip = ipv4(address), let network = ipv4(String(parts[0])), let prefix = Int(parts[1]) else { return false }
        return ip & (UInt32.max << (32 - prefix)) == network
    }
}

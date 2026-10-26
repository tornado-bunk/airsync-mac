import Foundation

nonisolated enum RelayUrlPolicy {
    static func normalize(_ raw: String) -> String? {
        let input = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: input.contains("://") ? input : "wss://\(input)"),
              let scheme = components.scheme, ["ws", "wss"].contains(scheme),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.port.map({ (1...65535).contains($0) }) ?? true else { return nil }
        components.scheme = scheme == "ws" && Self.isPrivateHost(host) ? "ws" : "wss"
        var path = components.path
        while path.hasSuffix("/") { path.removeLast() }
        if !path.hasSuffix("/ws") { path += "/ws" }
        components.path = path
        return components.string
    }

    static func isPrivateHost(_ host: String) -> Bool {
        if ["localhost", "::1", "[::1]"].contains(host) { return true }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.utf8.allSatisfy({ (48...57).contains($0) }),
                  part.count == 1 || part.first != "0",
                  let value = Int(part), (0...255).contains(value) else { return false }
            octets.append(value)
        }
        return octets[0] == 127 || octets[0] == 10 ||
            (octets[0] == 192 && octets[1] == 168) ||
            (octets[0] == 172 && (16...31).contains(octets[1]))
    }
}

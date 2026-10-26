import Foundation

/// Frames must be encrypted/authenticated before transmission. A fresh receiver
/// challenge rejects prior sessions; a sequence rejects duplicates in this session.
nonisolated final class RelayProtocol: @unchecked Sendable {
    private let role: String
    private let peerRole: String
    private let nonce: String
    private var peerNonce: String?
    private var sent: Int64 = 0
    private var received: Int64 = 0
    private let lock = NSLock()

    init(role: String, nonce: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()) {
        self.role = role
        self.peerRole = role == "mac" ? "android" : "mac"
        self.nonce = nonce
    }

    var hello: String { "AB1|hello|\(role)|\(nonce)" }

    func wrap(_ payload: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let peerNonce, sent < Int64.max else { return nil }
        sent += 1
        return "AB1|data|\(role)|\(nonce)|\(peerNonce)|\(sent)|\(payload)"
    }

    /// Returns an application payload and, only for a new peer challenge, a hello reply.
    func receive(_ plaintext: String) -> (payload: String?, reply: String?) {
        lock.lock()
        defer { lock.unlock() }
        let parts = plaintext.split(separator: "|", maxSplits: 6, omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "AB1", parts[2] == peerRole else { return (nil, nil) }
        if parts.count == 4, parts[1] == "hello",
           parts[3].count == 32, parts[3].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
            let changed = peerNonce != parts[3]
            peerNonce = parts[3]
            // Do not reset counters on hello: replaying hello must not re-enable old data.
            return (nil, changed ? hello : nil)
        }
        guard parts.count == 7, parts[1] == "data", parts[3] == peerNonce,
              parts[4] == nonce, let sequence = Int64(parts[5]), sequence > received else { return (nil, nil) }
        received = sequence
        return (parts[6], nil)
    }
}

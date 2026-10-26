import Foundation
import Combine
import CryptoKit
import SystemConfiguration
import OSLog

nonisolated struct LANBinding: Equatable, Sendable {
    let fingerprint: String
    let subnet: String
    let gateway: String
}

/// The shared catalog is scoped to the pairing key. Recognition always uses local observations.
nonisolated final class TrustedLANNetwork: ObservableObject, @unchecked Sendable {
    static let shared = TrustedLANNetwork()
    @Published private(set) var networks: [TrustedNetwork] = []
    @Published private(set) var status = "Unknown network · using Airbridge"
    @Published private(set) var isEnrolling = false
    private let lock = NSRecursiveLock()
    private let defaults: UserDefaults
    private let bindingLookup: () -> [String: LANBinding]
    private var storageKey = ""
    private var entries: [String: TrustedNetwork] = [:]
    private var bindings: [String: LANBinding] = [:]
    private var requests: [String: (name: String, expires: Date, fingerprints: Set<String>)] = [:]

    init(defaults: UserDefaults = .standard, bindingLookup: (() -> [String: LANBinding])? = nil) {
        self.defaults = defaults
        self.bindingLookup = bindingLookup ?? Self.currentBindings
    }

    private func load() {
        let key = defaults.string(forKey: "encryptionKey").flatMap { Data(base64Encoded: $0) }
        let next = key.map { "trustedNetworks.v1." + Self.fingerprint($0) } ?? ""
        guard next != storageKey else { return }
        storageKey = next
        requests.removeAll()
        entries = [:]
        if !next.isEmpty, let data = defaults.data(forKey: next), let saved = try? JSONDecoder().decode([TrustedNetwork].self, from: data) {
            for entry in saved where entry.isValid { entries[entry.id] = TrustedNetwork.merge(entries[entry.id], entry) }
        }
        if !next.isEmpty, defaults.object(forKey: next + ".initialPairing") == nil {
            defaults.set(!defaults.bool(forKey: "hasPairedDeviceOnce") && entries.isEmpty, forKey: next + ".initialPairing")
        }
    }

    var isAllowed: Bool {
        lock.lock(); defer { lock.unlock() }
        load()
        return entries.values.contains { !$0.deleted && matchesCurrentBinding($0) }
    }

    private func matchesCurrentBinding(_ entry: TrustedNetwork) -> Bool {
        bindings.values.contains { $0.fingerprint == entry.macFingerprint && $0.subnet == entry.subnet && $0.gateway == entry.gateway }
    }

    var allowedAddresses: [String] {
        lock.lock(); defer { lock.unlock() }
        load()
        return bindings.filter { _, binding in entries.values.contains { !$0.deleted && $0.macFingerprint == binding.fingerprint && $0.subnet == binding.subnet && $0.gateway == binding.gateway } }.keys.sorted()
    }

    var currentNetworkIDs: [String] {
        lock.lock(); defer { lock.unlock() }
        load()
        return entries.values.filter { !$0.deleted && matchesCurrentBinding($0) }.map(\.id).sorted()
    }

    func allows(networkID: String, localAddress: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        load()
        guard let record = entries[networkID], !record.deleted, let binding = bindings[localAddress] else { return false }
        return record.macFingerprint == binding.fingerprint && record.subnet == binding.subnet && record.gateway == binding.gateway
    }

    func refresh() {
        let current = bindingLookup()
        lock.lock()
        load()
        bindings = current
        requests = requests.filter { $0.value.expires > Date() }
        publish()
        lock.unlock()
    }

    private func publish(_ message: String? = nil) {
        let visible = entries.values.filter { !$0.deleted }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        let matched = visible.first(where: matchesCurrentBinding)
        let text = message ?? (requests.isEmpty ? matched.map { "Recognized: \($0.name)" } ?? "Unknown network · using Airbridge" : "Checking both devices on this network…")
        let pending = !requests.isEmpty
        DispatchQueue.main.async {
            self.networks = visible
            self.status = text
            self.isEnrolling = pending
        }
    }

    private func save() {
        guard !storageKey.isEmpty else { return }
        defaults.set(try? JSONEncoder().encode(Array(entries.values)), forKey: storageKey)
        publish()
    }

    func catalog() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        load()
        let data = (try? JSONEncoder().encode(Array(entries.values))) ?? Data("[]".utf8)
        return ["op": "catalog", "version": 1, "entries": (try? JSONSerialization.jsonObject(with: data)) ?? []]
    }

    func merge(_ payload: [String: Any]) {
        lock.lock(); defer { lock.unlock() }
        load()
        guard payload["version"] as? Int == 1, let raw = payload["entries"] as? [[String: Any]], raw.count <= 256,
              let data = try? JSONSerialization.data(withJSONObject: raw), data.count <= 262_144,
              let incoming = try? JSONDecoder().decode([TrustedNetwork].self, from: data), incoming.allSatisfy(\.isValid) else { return }
        for record in incoming where entries[record.id] != nil || entries.count < 256 { entries[record.id] = TrustedNetwork.merge(entries[record.id], record) }
        save()
    }

    func rename(_ id: String, name: String) {
        mutate(id, name: name, deleted: false)
    }

    func remove(_ id: String) { mutate(id, name: nil, deleted: true) }

    private func mutate(_ id: String, name: String?, deleted: Bool) {
        lock.lock()
        load()
        guard var entry = entries[id], !entry.deleted else { lock.unlock(); return }
        if let name {
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed.utf16.count <= 80 else { lock.unlock(); return }
            entry.name = trimmed
        }
        entry.deleted = deleted
        entry.revision = (entries.values.map(\.revision).max() ?? 0) + 1
        entry.editor = "mac"
        entries[id] = entry
        save()
        lock.unlock()
        let payload = catalog()
        DispatchQueue.main.async {
            WebSocketServer.shared.sendTrustedNetworkControl(payload)
            WebSocketServer.shared.checkNetworkChange()
        }
    }

    func beginEnrollment(name: String) {
        prepareEnrollment(requestID: UUID().uuidString.lowercased(), name: name)
    }

    func prepareEnrollment(requestID: String, name: String) {
        refresh()
        lock.lock()
        var name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        while name.utf16.count > 80 { name.removeLast() }
        guard UUID(uuidString: requestID) != nil, !name.isEmpty, !bindings.isEmpty, !storageKey.isEmpty, entries.count < 256 else {
            Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff").error("Network registration unavailable: bindings=\(self.bindings.count), pairingKey=\(!self.storageKey.isEmpty), entries=\(self.entries.count)")
            publish("Cannot register: connect both devices to the same local network.")
            lock.unlock(); return
        }
        requests[requestID] = (name, Date().addingTimeInterval(45), Set(bindings.values.map(\.fingerprint)))
        Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff").info("Network registration started: localBindings=\(self.bindings.count)")
        publish()
        let ips = bindings.keys.sorted()
        lock.unlock()
        DispatchQueue.main.async {
            WebSocketServer.shared.sendTrustedNetworkControl(["op": "prepare", "requestID": requestID, "name": name, "ips": ips, "port": Int(WebSocketServer.shared.localPort ?? Defaults.serverPort)])
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 45) {
            self.lock.lock()
            defer { self.lock.unlock() }
            if self.requests.removeValue(forKey: requestID) != nil {
                self.publish("Registration timed out. Keep both devices on the same network and retry.")
            }
        }
    }

    func finishKnownEnrollment(requestID: String, networkID: String) {
        lock.lock(); defer { lock.unlock() }
        guard let request = requests.removeValue(forKey: requestID), request.expires > Date(),
              let record = entries[networkID], !record.deleted,
              request.fingerprints.contains(record.macFingerprint), matchesCurrentBinding(record) else { return }
        rename(networkID, name: request.name)
    }

    func failEnrollment(requestID: String) {
        lock.lock(); defer { lock.unlock() }
        guard requests.removeValue(forKey: requestID) != nil else { return }
        publish("Local verification failed. Check the phone permissions and connect both devices to the same network, then retry.")
    }

    /// Called exclusively for an authenticated frame received on an actual LAN socket.
    func verifyProof(_ data: [String: Any], peerAddress: String) -> TrustedNetwork? {
        lock.lock(); defer { lock.unlock() }
        load()
        guard let target = data["target"] as? String, let binding = bindings[target],
              let fingerprint = data["fingerprint"] as? String, fingerprint.count == 64,
              data["subnet"] as? String == binding.subnet, data["gateway"] as? String == binding.gateway,
              data["address"] as? String == peerAddress, TrustedNetwork.contains(peerAddress, subnet: binding.subnet) else {
            Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff").error("LAN proof identity mismatch: targetKnown=\(self.bindings[data["target"] as? String ?? ""] != nil), peerMatches=\(data["address"] as? String == peerAddress)")
            return nil
        }
        if let existing = entries.values.first(where: { !$0.deleted && $0.macFingerprint == binding.fingerprint && $0.androidFingerprint == fingerprint && $0.subnet == binding.subnet && $0.gateway == binding.gateway }) {
            if let requestID = data["requestID"] as? String {
                finishKnownEnrollment(requestID: requestID, networkID: existing.id)
            }
            publish()
            return entries[existing.id] ?? existing
        }
        let requestID = data["requestID"] as? String ?? ""
        let request = requests[requestID]
        let initial = entries.isEmpty && defaults.bool(forKey: storageKey + ".initialPairing") && data["firstPairing"] as? Bool == true
        guard initial || (request.map { $0.expires > Date() && $0.fingerprints.contains(binding.fingerprint) } ?? false), entries.count < 256 else {
            Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff").notice("LAN proof requires explicit registration: initial=\(initial), pendingRequest=\(request != nil)")
            return nil
        }
        let record = TrustedNetwork(id: UUID().uuidString.lowercased(), name: request?.name ?? "Pairing network", macFingerprint: binding.fingerprint, androidFingerprint: fingerprint, subnet: binding.subnet, gateway: binding.gateway, revision: (entries.values.map(\.revision).max() ?? 0) + 1, editor: "mac", deleted: false)
        guard record.isValid else { return nil }
        entries[record.id] = record
        Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff").info("LAN network proof accepted; network registered")
        defaults.set(false, forKey: storageKey + ".initialPairing")
        requests.removeValue(forKey: requestID)
        save()
        return record
    }

    static func fingerprint(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    static func bindings(services: [[String: Any]], arpOutput: String) -> [String: LANBinding] {
        var result: [String: LANBinding] = [:]
        for service in services {
            guard let gateway = service["Router"] as? String, TrustedNetwork.ipv4(gateway) != nil,
                  let interface = service["InterfaceName"] as? String, interface.hasPrefix("en"),
                  let addresses = service["Addresses"] as? [String], let masks = service["SubnetMasks"] as? [String] else { continue }
            // macOS already resolves the gateway for each service, including Ethernet.
            let resolved = service["ARPResolvedIPAddress"] as? String == gateway ? service["ARPResolvedHardwareAddress"] as? String : nil
            let lines = resolved.map { ["? (\(gateway)) at \($0) on \(interface)"] } ?? arpOutput.split(separator: "\n").map(String.init)
            for line in lines {
                let fields = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
                guard fields.count >= 6, fields[1] == "(\(gateway))", fields[2] == "at", fields[4] == "on", fields[5] == interface else { continue }
                let parts = fields[3].split(separator: ":", omittingEmptySubsequences: false)
                let bytes = parts.compactMap { (1...2).contains($0.count) ? UInt8($0, radix: 16) : nil }
                guard parts.count == 6, bytes.count == 6, bytes.contains(where: { $0 != 0 }), bytes[0] & 1 == 0 else { continue }
                let mac = bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
                for (address, mask) in zip(addresses, masks) {
                    guard let subnet = TrustedNetwork.subnet(address: address, mask: mask) else { continue }
                    let fingerprint = fingerprint(Data("v1|\(mac)|\(gateway)|\(subnet)".utf8))
                    result[address] = LANBinding(fingerprint: fingerprint, subnet: subnet, gateway: gateway)
                }
            }
        }
        return result
    }

    private static func currentBindings() -> [String: LANBinding] {
        guard let store = SCDynamicStoreCreate(nil, "AirSync trusted networks" as CFString, nil, nil),
              let services = SCDynamicStoreCopyMultiple(store, nil, ["State:/Network/Service/.*/IPv4"] as CFArray) as? [String: [String: Any]] else { return [:] }
        let resolved = bindings(services: Array(services.values), arpOutput: "")
        let physical = services.values.filter { ($0["InterfaceName"] as? String)?.hasPrefix("en") == true && $0["Router"] != nil }
        if !physical.isEmpty && physical.allSatisfy({ service in
            (service["Addresses"] as? [String] ?? []).contains { resolved[$0] != nil }
        }) { return resolved }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        process.arguments = ["-an"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return resolved }
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return resolved }
        let result = bindings(services: Array(services.values), arpOutput: output)
        // Prime only missing gateways: a cold ARP cache must not require Internet access.
        for service in services.values {
            guard let gateway = service["Router"] as? String, TrustedNetwork.ipv4(gateway) != nil,
                  let interface = service["InterfaceName"] as? String, interface.hasPrefix("en"),
                  let addresses = service["Addresses"] as? [String], !addresses.contains(where: { result[$0] != nil }) else { continue }
            primeGateway(gateway, interface: interface)
        }
        return result
    }

    private static func primeGateway(_ gateway: String, interface: String) {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard descriptor >= 0 else { return }
        defer { Darwin.close(descriptor) }
        var index = if_nametoindex(interface)
        guard index != 0, setsockopt(descriptor, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout.size(ofValue: index))) == 0 else { return }
        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = UInt16(9).bigEndian
        guard inet_pton(AF_INET, gateway, &destination.sin_addr) == 1 else { return }
        var byte: UInt8 = 0
        withUnsafePointer(to: &destination) { address in
            address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = sendto(descriptor, &byte, 1, MSG_DONTWAIT, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }
}

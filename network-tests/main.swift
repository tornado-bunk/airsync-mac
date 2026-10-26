import Foundation
import AppKit
import Swifter

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fatalError(message) }
}
func pump(_ seconds: TimeInterval) { RunLoop.main.run(until: Date().addingTimeInterval(seconds)) }
func wait(_ message: String, timeout: TimeInterval = 6, until predicate: () -> Bool) {
    let end = Date().addingTimeInterval(timeout)
    while !predicate() && Date() < end { pump(0.05) }
    expect(predicate(), message)
}

func testPairingNetwork() {
    let suite = "AirSync-network-tests-\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set(Data(repeating: 1, count: 32).base64EncodedString(), forKey: "encryptionKey")
    let home = LANBinding(fingerprint: String(repeating: "a", count: 64), subnet: "192.168.1.0/24", gateway: "192.168.1.1")
    var bindings = ["192.168.1.2": home]
    let policy = TrustedLANNetwork(defaults: defaults, bindingLookup: { bindings })
    policy.refresh()
    func proof(_ target: String = "192.168.1.2", phone: String = String(repeating: "b", count: 64), request: String = "") -> [String: Any] {
        ["target": target, "fingerprint": phone, "subnet": "192.168.1.0/24", "gateway": "192.168.1.1", "address": "192.168.1.5", "requestID": request, "firstPairing": true]
    }
    expect(!policy.isAllowed, "A reachable LAN alone must not be trusted")
    defaults.set(true, forKey: "hasPairedDeviceOnce")
    // The relay device handshake can finish while the first LAN proof is in flight.
    expect(policy.verifyProof(proof(), peerAddress: "192.168.1.9") == nil, "Claimed address must match the actual LAN peer")
    var record = policy.verifyProof(proof(), peerAddress: "192.168.1.5")!
    defaults.set(true, forKey: "hasPairedDeviceOnce")
    expect(policy.isAllowed && policy.allows(networkID: record.id, localAddress: "192.168.1.2"), "First local pairing registers the network")
    expect(policy.verifyProof(proof(phone: String(repeating: "c", count: 64)), peerAddress: "192.168.1.5") == nil, "Guest SSID cannot inherit router authorization")
    let renameRequest = UUID().uuidString.lowercased()
    policy.prepareEnrollment(requestID: renameRequest, name: "Home")
    policy.finishKnownEnrollment(requestID: renameRequest, networkID: record.id)
    let named = policy.catalog()["entries"] as! [[String: Any]]
    expect(named.count == 1 && named.first?["name"] as? String == "Home", "Adding a known network updates its name without duplicating it")
    policy.finishKnownEnrollment(requestID: UUID().uuidString, networkID: record.id)
    let proofRenameRequest = UUID().uuidString.lowercased()
    policy.prepareEnrollment(requestID: proofRenameRequest, name: "Home LAN")
    let renamed = policy.verifyProof(proof(request: proofRenameRequest), peerAddress: "192.168.1.5")!
    expect(renamed.id == record.id && renamed.name == "Home LAN", "Enrollment through a fresh LAN proof also applies the requested name")
    let revokedID = record.id
    policy.remove(revokedID)
    expect(!policy.isAllowed && !policy.allows(networkID: revokedID, localAddress: "192.168.1.2"), "Revocation removes local authorization immediately")
    expect(policy.verifyProof(proof(), peerAddress: "192.168.1.5") == nil, "Deleting the last entry cannot restore automatic first pairing")
    let readd = UUID().uuidString.lowercased()
    policy.prepareEnrollment(requestID: readd, name: "Home again")
    record = policy.verifyProof(proof(request: readd), peerAddress: "192.168.1.5")!
    expect(record.id != revokedID, "Explicitly re-adding creates a fresh ID")
    bindings = ["192.168.1.50": home]
    policy.refresh()
    expect(policy.isAllowed && policy.allows(networkID: record.id, localAddress: "192.168.1.50"), "DHCP address changes preserve network identity")
    expect(!policy.allows(networkID: record.id, localAddress: "192.168.1.2"), "Old local addresses must not remain authorized")
    bindings = ["192.168.1.2": LANBinding(fingerprint: String(repeating: "d", count: 64), subnet: home.subnet, gateway: home.gateway)]
    policy.refresh()
    expect(!policy.isAllowed, "Same subnet and gateway IP at university must remain on relay")
    expect(policy.verifyProof(proof(), peerAddress: "192.168.1.5") == nil, "University cannot enroll automatically after first pairing")
    let request = UUID().uuidString.lowercased()
    policy.prepareEnrollment(requestID: request, name: "Office")
    expect(policy.verifyProof(proof(request: "wrong-request"), peerAddress: "192.168.1.5") == nil, "Registration requires a matching pending request")
    expect(policy.verifyProof(proof(request: request), peerAddress: "192.168.1.5") != nil, "Explicit registration may add another network")
    bindings = [:]
    policy.refresh()
    expect(!policy.isAllowed, "Unknown/offline network fails closed")
    defaults.set(Data(repeating: 2, count: 32).base64EncodedString(), forKey: "encryptionKey")
    bindings = ["192.168.1.2": home]
    policy.refresh()
    expect(!policy.isAllowed, "Pairing key changes isolate catalogs")
    expect(policy.verifyProof(proof(), peerAddress: "192.168.1.5") == nil, "An existing pairing with unknown trust cannot enroll silently")

    let offlineRename = TrustedNetwork(id: record.id, name: "Offline rename", macFingerprint: record.macFingerprint, androidFingerprint: record.androidFingerprint, subnet: record.subnet, gateway: record.gateway, revision: 3, editor: "android", deleted: false)
    var removed = record
    removed.revision = 2; removed.deleted = true
    expect(TrustedNetwork.merge(offlineRename, removed) == removed && TrustedNetwork.merge(removed, offlineRename) == removed, "Deletion wins over offline rename in either order")
    var concurrent = offlineRename
    concurrent.editor = "mac"
    expect(TrustedNetwork.merge(concurrent, offlineRename) == concurrent && TrustedNetwork.merge(offlineRename, concurrent) == concurrent, "Concurrent edits converge")
    var impostor = record
    impostor.macFingerprint = String(repeating: "e", count: 64); impostor.revision = 100
    expect(TrustedNetwork.merge(record, impostor) == record, "Rename cannot alter network identity")
    expect(TrustedNetwork.subnet(address: "10.21.3.4", mask: "255.240.0.0") == "10.16.0.0/12", "CIDR calculation matches Android")
    expect(TrustedNetwork.subnet(address: "192.168.1.1", mask: "255.0.255.0") == nil, "Invalid subnet masks fail closed")

    let services: [[String: Any]] = [
        ["InterfaceName": "en0", "Router": "192.168.1.1", "Addresses": ["192.168.1.2"], "SubnetMasks": ["255.255.255.0"]],
        ["InterfaceName": "en8", "Router": "192.168.1.1", "Addresses": ["192.168.1.3"], "SubnetMasks": ["255.255.255.0"]],
        ["InterfaceName": "utun1", "Router": "10.1.0.1", "Addresses": ["10.1.0.2"], "SubnetMasks": ["255.255.255.0"]]
    ]
    let arp = """
    ? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]
    ? (192.168.1.1) at 0a:0b:0c:0d:0e:0f on en8 ifscope [ethernet]
    ? (192.168.1.9) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
    ? (10.1.0.1) at 11:22:33:44:55:66 on utun1
    """
    let parsed = TrustedLANNetwork.bindings(services: services, arpOutput: arp)
    expect(parsed.count == 2 && parsed["192.168.1.2"] == parsed["192.168.1.3"], "Ethernet and Wi-Fi share identity; VPN/neighbors are excluded")
    var resolvedServices = services
    for index in 0...1 {
        resolvedServices[index]["ARPResolvedIPAddress"] = "192.168.1.1"
        resolvedServices[index]["ARPResolvedHardwareAddress"] = "0a:0b:0c:0d:0e:0f"
    }
    expect(TrustedLANNetwork.bindings(services: resolvedServices, arpOutput: "") == parsed, "Native resolved gateway identifies Ethernet and Wi-Fi without an ARP subprocess")
    resolvedServices[0]["ARPResolvedIPAddress"] = "192.168.1.254"
    expect(TrustedLANNetwork.bindings(services: resolvedServices, arpOutput: "").count == 1, "Native gateway identity must refer to the current router")
    expect(TrustedLANNetwork.bindings(services: services, arpOutput: "? (192.168.1.1) at (incomplete) on en0").isEmpty, "Incomplete ARP cannot grant LAN")
    print("PASS: first pairing, guest rejection, same-subnet university, DHCP, catalog merge, VPN exclusion and offline fallback")
}

testPairingNetwork()
let port = CommandLine.arguments[1]
UserDefaults.standard.setVolatileDomain([
    "appConnectionMode": "dynamic", "airBridgeEnabled": true,
    "airBridgeRelayURL": "ws://127.0.0.1:\(port)", "airBridgePairingId": "network-test-pair",
    "isManuallyDisconnected": false
], forName: UserDefaults.argumentDomain)
let relay = AirBridgeClient.shared
let server = WebSocketServer.shared
let began = ProcessInfo.processInfo.systemUptime
relay.connect()
wait("Silent relay handshake must time out and reconnect", timeout: 24) { relay.connectionState == .relayActive }
expect(ProcessInfo.processInfo.systemUptime - began >= 14, "Fixture did not exercise handshake timeout")
pump(0.2)
expect(server.relayActivations == 1, "Only the recovered relay session may activate")
relay.sendText("{\"type\":\"testClose\"}")
wait("Closed relay socket must reconnect") { server.relayActivations == 2 }
relay.sendText("{\"type\":\"testDropWebSocketPongs\"}")
wait("Missing transport pong must reconnect even if application pong arrives", timeout: 18) { server.relayActivations == 3 }
print("PASS: handshake deadline, socket failure and relay pong deadline")

let stale = WebSocketSession()
server.activeSessions = [stale]
server.primarySessionID = ObjectIdentifier(stale)
server.lastActivity[ObjectIdentifier(stale)] = Date().addingTimeInterval(-25)
server.sessionLocalAddresses[ObjectIdentifier(stale)] = "192.168.1.2"
server.performPing()
expect(stale.socket.closed && server.activeSessions.isEmpty && server.primarySessionID == nil, "Stale LAN must actually close and be removed")
expect(server.sessionLocalAddresses.isEmpty, "Session address bookkeeping must be removed")
pump(0.1)
expect(AppState.shared.disconnectCount == 0, "LAN loss must preserve a working relay/device")
let replacement = WebSocketSession()
server.activeSessions = [replacement]
server.primarySessionID = ObjectIdentifier(replacement)
server.lastActivity[ObjectIdentifier(replacement)] = Date()
server.removeLocalSession(stale, reason: "late_old_callback")
expect(server.hasActiveLocalSession(), "Old callback must not remove a newer primary")
server.performPing()
expect(!replacement.socket.closed, "Healthy LAN must not be evicted")
print("PASS: stale LAN closes without listener restart, relay stays available, old callback preserves new LAN")

let activations = server.relayActivations
NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.didWakeNotification, object: nil)
relay.disconnect()
pump(2)
expect(relay.connectionState == .disconnected && server.relayActivations == activations, "Manual disconnect must cancel pending wake recovery")
relay.recoverConnection(reason: "automatic test retry")
NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.didWakeNotification, object: nil)
pump(1.5)
expect(server.relayActivations == activations, "Automatic recovery must preserve manual disconnect")
print("PASS: manual disconnect survives wake and automatic retries")
print("All network handoff regressions passed")

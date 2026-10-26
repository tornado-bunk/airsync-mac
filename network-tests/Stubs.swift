import Foundation
import CryptoKit
import Swifter

// Transport/lifecycle tests use plaintext fixtures. Production encryption is not tested here.
func encryptMessage(_ text: String, using key: SymmetricKey) -> String? { text }
func decryptMessage(_ text: String, using key: SymmetricKey) -> String? { text }
enum Defaults { static let serverPort: UInt16 = 6996 }
enum KeychainStorage {
    static func string(for key: String) -> String? { "dummy-network-test-secret" }
    static func set(_ value: String, for key: String) {}
}
extension UserDefaults {
    var isManuallyDisconnected: Bool { bool(forKey: "isManuallyDisconnected") }
}
final class AppState {
    static let shared = AppState()
    enum AppConnectionMode: String { case dynamic, network }
    var selectedNetworkAdapterName: String?
    var isConnectionWeak = false
    var adbConnected = false
    var disconnectCount = 0
    func updatePeerTransportHint(_ transport: String?) {}
    func disconnectDevice(manual: Bool, unlessReconnected: Bool) { disconnectCount += 1 }
}
final class WebSocketServer {
    static let shared = WebSocketServer()
    var symmetricKey: SymmetricKey? = SymmetricKey(data: Data(repeating: 1, count: 32))
    var localPort: UInt16? = 6996
    let lock = NSRecursiveLock()
    var activeSessions: [WebSocketSession] = []
    var primarySessionID: ObjectIdentifier?
    var lastActivity: [ObjectIdentifier: Date] = [:]
    var sessionProofNonces: [ObjectIdentifier: String] = [:]
    var sessionNetworkIDs: [ObjectIdentifier: String] = [:]
    var sessionLocalAddresses: [ObjectIdentifier: String] = [:]
    var pingTimer: Timer?
    let pingInterval = 4.5
    let activityTimeout = 20.0
    var relayActivations = 0
    var lanEvents: [Bool] = []
    func getLocalIPAddress(adapterName: String?) -> String? { "192.168.1.2" }
    func hasActiveLocalSession() -> Bool {
        activeSessions.contains { ObjectIdentifier($0) == primarySessionID }
    }
    func resetTransportNegotiationState() { relayActivations += 1 }
    func sendPeerTransportStatus(_ status: String) {}
    func sendWakeViaRelay() {}
    func sendTrustedNetworkControl(_ data: [String: Any]) {}
    func checkNetworkChange() {}
    func handleRelayedMessage(_ text: String) {
        if text.contains("pong") { AirBridgeClient.shared.processPong() }
    }
    func publishLanTransportState(isActive: Bool, reason: String) { lanEvents.append(isActive) }
}
final class MacRemoteManager {
    static let shared = MacRemoteManager()
    func stopVolumeMonitoring() {}
}
enum ADBConnector { static func disconnectADB() {} }
final class BLECentralManager {
    static let shared = BLECentralManager()
    var isAuthenticated = false
}

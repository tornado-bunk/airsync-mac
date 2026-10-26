//
//  WebSocketServer.swift
//  airsync-mac
//
//  Created by Sameera Sandakelum on 2025-07-28.
//

import Foundation
import Swifter
import CryptoKit
import UserNotifications
import Combine
import Network

class WebSocketServer: ObservableObject {
    static let shared = WebSocketServer()
    
    internal var server = HttpServer()
    internal var activeSessions: [WebSocketSession] = []
    internal var primarySessionID: ObjectIdentifier?
    internal var pingTimer: Timer?
    internal let pingInterval: TimeInterval = 4.5
    internal var lastActivity: [ObjectIdentifier: Date] = [:]
    internal var sessionProofNonces: [ObjectIdentifier: String] = [:]
    internal var sessionNetworkIDs: [ObjectIdentifier: String] = [:]
    internal var sessionLocalAddresses: [ObjectIdentifier: String] = [:]
    internal let activityTimeout: TimeInterval = 20.0
    
    @Published var symmetricKey: SymmetricKey?
    @Published var localPort: UInt16?
    @Published var localIPAddress: String?
    @Published var connectedDevice: Device?
    @Published var notifications: [Notification] = []
    @Published var deviceStatus: DeviceStatus?

    internal var lastTrustedLANAllowed = false
    internal var lastTrustedLANNetworkIDs = Set<String>()
    internal var lastKnownIP: String?
    internal var networkMonitorTimer: Timer?
    internal var networkPathMonitor: NWPathMonitor?
    internal var pendingNetworkChangeWorkItem: DispatchWorkItem?
    internal var serverLifecycleGeneration = 0
    internal var restartRequestGeneration = 0
    internal let networkMonitorQueue = DispatchQueue(label: "com.airsync.networkmonitor", qos: .utility)
    internal let networkCheckInterval: TimeInterval = 10.0
    internal let lock = NSRecursiveLock()
    internal let fileQueue = DispatchQueue(label: "com.airsync.fileio")
    private let jsonDecoder = JSONDecoder()
    
    internal var servers: [String: HttpServer] = [:]
    internal var isListeningOnAll = false

    internal var incomingFiles: [String: IncomingFileIO] = [:]
    internal var incomingFilesChecksum: [String: String] = [:]
    internal var outgoingAcks: [String: Set<Int>] = [:]

    internal let maxChunkRetries = 3
    internal let ackWaitMs: UInt16 = 2000

    internal var lastKnownAdapters: [(name: String, address: String)] = []
    internal var lastLoggedSelectedAdapter: (name: String, address: String)? = nil
    internal let transportGenerationTTL: TimeInterval = 120
    internal var transportGenerationCounter: Int64 = 0
    internal var activeTransportGeneration: Int64 = 0
    internal var activeTransportGenerationStartedAt: Date?
    internal var validatedTransportGeneration: Int64 = 0
    internal let lanDownDebounceSeconds: TimeInterval = 2.5
    internal var pendingLanDownWorkItem: DispatchWorkItem?
    internal var pendingRestartWorkItem: DispatchWorkItem?

    // Emits immediate events when the primary LAN WebSocket session starts or ends.
    // Used by AppState/UI to update LAN vs relay indicators without polling.
    internal let lanSessionEvents = PassthroughSubject<Bool, Never>() // true = started, false = ended
    internal var lastPublishedLanState: Bool?

    init() {
        loadOrGenerateSymmetricKey()
        setupWebSocket(for: server)
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let err = error {
                print("[websocket] Notification auth error: \(err)")
            } else {
                print("[websocket] Notification permission granted: \(granted)")
            }
        }
    }

    /// Starts the WebSocket server on the specified port.
    /// Handles binding to a specific network adapter or all available interfaces if "auto" is selected.
    func start(port: UInt16 = Defaults.serverPort) {
        DispatchQueue.main.async {
            AppState.shared.webSocketStatus = .starting
        }

        let adapterName = AppState.shared.selectedNetworkAdapterName
        lock.lock()
        serverLifecycleGeneration += 1
        let generation = serverLifecycleGeneration
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            guard generation == self.serverLifecycleGeneration else {
                self.lock.unlock()
                return
            }
            do {
                guard port > 0 else { throw NSError(domain: "WebSocketServer", code: 1) }
                self.stopAllServers()
                let listener = HttpServer()
                self.setupWebSocket(for: listener)
                // A wildcard listener survives interface changes, including starting offline.
                // Swifter.peername truncates IPv6 sockaddr; LAN identity currently uses IPv4.
                try listener.start(in_port_t(port), forceIPv4: true)
                self.servers["any"] = listener
                self.isListeningOnAll = true
                self.lock.unlock()
                DispatchQueue.main.async {
                    self.lock.lock()
                    let isCurrent = generation == self.serverLifecycleGeneration
                    self.lock.unlock()
                    guard isCurrent else { return }
                    let ip = self.getLocalIPAddress(adapterName: adapterName)
                    self.localPort = port
                    self.localIPAddress = ip
                    self.lastKnownIP = ip
                    self.lastKnownAdapters = self.getAvailableNetworkAdapters()
                    AppState.shared.webSocketStatus = .started(port: port, ip: ip)
                    TrustedLANNetwork.shared.refresh()
                    self.lastTrustedLANAllowed = TrustedLANNetwork.shared.isAllowed
                    self.startNetworkMonitoring()
                    DiscoveryManager.shared.broadcastBurst()
                    self.sendWakeViaRelay()
                }
            } catch {
                self.lock.unlock()
                DispatchQueue.main.async { AppState.shared.webSocketStatus = .failed(error: "\(error)") }
            }
        }
    }

    internal func stopAllServers() {
        for (_, server) in servers {
            server.stop()
        }
        servers.removeAll()
    }

    func requestRestart(reason: String, delay: TimeInterval = 0.35, port: UInt16? = nil) {
        lock.lock()
        let restartPort = port ?? localPort ?? Defaults.serverPort
        pendingRestartWorkItem?.cancel()
        restartRequestGeneration += 1
        let generation = restartRequestGeneration
        lock.unlock()

        let workItem = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            let isCurrent = generation == self.restartRequestGeneration
            self.lock.unlock()
            guard isCurrent else { return }
            self.stop()
            self.start(port: restartPort)
        }

        lock.lock()
        pendingRestartWorkItem = workItem
        lock.unlock()
        
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
    }

    func stop() {
        lock.lock()
        serverLifecycleGeneration += 1
        restartRequestGeneration += 1
        pendingRestartWorkItem?.cancel()
        pendingRestartWorkItem = nil
        stopAllServers()
        activeSessions.removeAll()
        lastActivity.removeAll()
        sessionLocalAddresses.removeAll()
        sessionNetworkIDs.removeAll()
        sessionProofNonces.removeAll()
        primarySessionID = nil
        pendingLanDownWorkItem?.cancel()
        pendingLanDownWorkItem = nil
        stopPing()
        lock.unlock()
        publishLanTransportState(isActive: false, reason: "server_stop")
        DispatchQueue.main.async { AppState.shared.webSocketStatus = .stopped }
        stopNetworkMonitoring()
    }

    /// Returns true only when a primary LAN WebSocket session is currently active.
    func hasActiveLocalSession() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let pId = primarySessionID else { return false }
        return activeSessions.contains(where: { ObjectIdentifier($0) == pId })
    }

    /// Publishes LAN transport state changes in one place to keep UI and routing hints consistent.
    internal func publishLanTransportState(isActive: Bool, reason: String) {
        // Debounce LAN-down transitions to avoid rapid relay<->lan oscillation when the
        // local socket briefly stalls but recovers.
        if !isActive {
            lock.lock()
            pendingLanDownWorkItem?.cancel()
            let work = DispatchWorkItem { [weak self] in
                guard let self else { return }
                if self.hasActiveLocalSession() {
                    return
                }
                self.publishLanTransportStateNow(isActive: false, reason: "\(reason)_debounced")
            }
            pendingLanDownWorkItem = work
            let debounce = lanDownDebounceSeconds
            lock.unlock()

            DispatchQueue.main.asyncAfter(deadline: .now() + debounce, execute: work)
            return
        }

        lock.lock()
        pendingLanDownWorkItem?.cancel()
        pendingLanDownWorkItem = nil
        lock.unlock()
        publishLanTransportStateNow(isActive: true, reason: reason)
    }

    private func publishLanTransportStateNow(isActive: Bool, reason _reason: String) {
        lock.lock()
        let previous = lastPublishedLanState
        if previous == isActive {
            lock.unlock()
            return
        }
        lastPublishedLanState = isActive
        lock.unlock()

        DispatchQueue.main.async {
            self.lanSessionEvents.send(isActive)
            AppState.shared.updatePeerTransportHint(isActive ? "wifi" : "relay")
        }
        sendPeerTransportStatus(isActive ? "wifi" : "relay")
    }

    internal func nextTransportGeneration() -> Int64 {
        lock.lock()
        transportGenerationCounter += 1
        let value = transportGenerationCounter
        lock.unlock()
        return value
    }

    internal func beginTransportRound(_ generation: Int64, reason _reason: String) {
        guard generation > 0 else { return }
        lock.lock()
        transportGenerationCounter = max(transportGenerationCounter, generation)
        activeTransportGeneration = generation
        activeTransportGenerationStartedAt = Date()
        validatedTransportGeneration = 0
        lock.unlock()
    }

    internal func resetTransportNegotiationState() {
        lock.lock()
        transportGenerationCounter = 0
        activeTransportGeneration = 0
        activeTransportGenerationStartedAt = nil
        validatedTransportGeneration = 0
        lock.unlock()
    }

    internal func isTransportGenerationActive(_ generation: Int64) -> Bool {
        guard generation > 0 else { return false }
        lock.lock()
        let current = activeTransportGeneration
        let startedAt = activeTransportGenerationStartedAt
        lock.unlock()
        guard current == generation, let startedAt else { return false }
        return Date().timeIntervalSince(startedAt) <= transportGenerationTTL
    }

    internal func acceptIncomingTransportGeneration(_ generation: Int64, reason: String) -> Bool {
        guard generation > 0 else { return false }
        lock.lock()
        let current = activeTransportGeneration
        let startedAt = activeTransportGenerationStartedAt
        lock.unlock()

        if current == 0 {
            beginTransportRound(generation, reason: "incoming_init:\(reason)")
            return true
        }
        if current == generation {
            return true
        }
        // Compatibility bridge: older builds used timestamp-based generations.
        // If we detect mixed formats, prefer the incoming monotonic counter round.
        if current > 1_000_000_000_000 && generation < 1_000_000_000 {
            beginTransportRound(generation, reason: "incoming_legacy_format_reset:\(reason)")
            return true
        }
        if generation > current || (startedAt.map { Date().timeIntervalSince($0) > transportGenerationTTL } ?? false) {
            beginTransportRound(generation, reason: "incoming_rollover:\(reason)")
            return true
        }
        return false
    }

    internal func markTransportGenerationValidated(_ generation: Int64, reason _reason: String) {
        guard isTransportGenerationActive(generation) else { return }
        lock.lock()
        validatedTransportGeneration = generation
        lock.unlock()
    }

    internal func isTransportGenerationValidated(_ generation: Int64) -> Bool {
        guard generation > 0 else { return false }
        lock.lock()
        let validated = validatedTransportGeneration
        lock.unlock()
        return validated == generation
    }

    /// Configures WebSocket routes and event callbacks.
    /// Handles message decryption before passing payload to the message router.
    private func setupWebSocket(for server: HttpServer) {
        server["/socket"] = websocket(
            text: { [weak self] session, text in
                guard let self = self else { return }
                let decryptedData: Data?
                if let key = self.symmetricKey {
                    decryptedData = decryptMessageToData(text, using: key)
                } else {
                    decryptedData = text.data(using: .utf8)
                }

                guard let data = decryptedData, !data.isEmpty else { return }

                self.lock.lock()
                guard self.activeSessions.contains(where: { $0 === session }) else { self.lock.unlock(); return }
                self.lastActivity[ObjectIdentifier(session)] = Date()
                self.lock.unlock()
                DispatchQueue.main.async {
                    if AppState.shared.isConnectionWeak {
                        AppState.shared.isConnectionWeak = false
                    }
                }

                do {
                    let message = try self.jsonDecoder.decode(Message.self, from: data)
                    if message.type == .status {
                        // Pong / keepalive check
                        if let dict = message.data.value as? [String: Any],
                           (dict["type"] as? String) == "pong" {
                            return
                        }
                    }

                    if message.type == .fileChunk || message.type == .fileChunkAck || message.type == .fileTransferComplete || message.type == .fileTransferInit {
                         self.handleMessage(message, session: session)
                    } else {
                        DispatchQueue.main.async { self.handleMessage(message, session: session) }
                    }
                } catch {
                    print("[websocket] JSON decode failed: \(error)")
                }
            },
            binary: { [weak self] session, _ in
                self?.lock.lock()
                self?.lastActivity[ObjectIdentifier(session)] = Date()
                self?.lock.unlock()
                DispatchQueue.main.async {
                    if AppState.shared.isConnectionWeak {
                        AppState.shared.isConnectionWeak = false
                    }
                }
            },
            connected: { [weak self] session in
                guard let self = self else { return }
                self.lock.lock()
                guard self.activeSessions.count < 8 else {
                    self.lock.unlock()
                    session.socket.close()
                    return
                }
                let sessionId = ObjectIdentifier(session)
                self.lastActivity[sessionId] = Date()
                self.activeSessions.append(session)
                let sessionCount = self.activeSessions.count
                self.lock.unlock()

                if sessionCount == 1 {
                    MacRemoteManager.shared.startVolumeMonitoring()
                    self.startPing()
                }

            },
            disconnected: { [weak self] session in
                guard let self = self else { return }
                self.removeLocalSession(session, reason: "socket_disconnected")
            }
        )
    }

    // MARK: - AirBridge Relay Integration

    /// Handles a text message received from the AirBridge relay (Android → Relay → Mac).
    /// Receives only authenticated, replay-checked plaintext from AirBridgeClient.
    func handleRelayedMessage(_ text: String) {
        // AirBridgeClient has already authenticated the session frame and decrypted it.
        let decryptedText = text

        guard let data = decryptedText.data(using: .utf8) else {
            print("[transport] RX via RELAY dropped: UTF-8 conversion failed")
            return
        }

        // Accept keepalive packets that omit "data" (e.g. {"type":"pong"}).
        if let jsonObj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let type = jsonObj["type"] as? String {
            if type == MessageType.pong.rawValue {
                AirBridgeClient.shared.processPong()
                return
            }
            if type == MessageType.ping.rawValue {
                let pongPayload = #"{"type":"pong"}"#
                AirBridgeClient.shared.sendText(pongPayload)
                return
            }
        }

        do {
            let message = try JSONDecoder().decode(Message.self, from: data)

            // Handle Pong for AirBridge keepalive
            if message.type == .pong {
                AirBridgeClient.shared.processPong()
                return
            }

            DispatchQueue.main.async {
                self.handleRelayedMessageInternal(message)
            }
        } catch {
            print("[airbridge] Failed to decode relayed message: \(error)")
        }
    }



    /// Internal router for relayed messages.
    /// Always uses the relay permission set, including when a LAN session is also active.
    private func handleRelayedMessageInternal(_ message: Message) {
        // For the device handshake, we handle it entirely within the relay path
        if message.type == .device {
            if let dict = message.data.value as? [String: Any],
               let name = dict["name"] as? String,
               let ip = dict["ipAddress"] as? String,
               let port = dict["port"] as? Int {

                let version = dict["version"] as? String ?? "2.0.0"
                let adbPorts = dict["adbPorts"] as? [String] ?? []
                let deviceId = dict["deviceId"] as? String ?? ""

                DispatchQueue.main.async {
                    AppState.shared.device = Device(
                        name: name,
                        ipAddress: ip,
                        port: port,
                        version: version,
                        adbPorts: adbPorts,
                        deviceId: deviceId
                    )
                }

                if let base64 = dict["wallpaper"] as? String {
                    DispatchQueue.main.async {
                        AppState.shared.currentDeviceWallpaperBase64 = base64
                    }
                }

                sendMacInfoViaRelay()
            }
            return
        }

        lock.lock()
        let staleSession = activeSessions.first {
            ObjectIdentifier($0) == primarySessionID && Date().timeIntervalSince(lastActivity[ObjectIdentifier($0)] ?? .distantPast) > activityTimeout
        }
        lock.unlock()
        if let staleSession {
            removeLocalSession(staleSession, reason: "stale_session_during_relay_rx")
            staleSession.socket.close()
        }

        // Transport permissions follow the source of the frame, not LAN availability.
        handleRelayOnlyMessage(message)
    }

    /// Sends macInfo response back through the relay instead of the local session.
    private func sendMacInfoViaRelay() {
        let macName = AppState.shared.myDevice?.name ?? (Host.current().localizedName ?? "My Mac")
        let isPlusSubscription = AppState.shared.isPlus
        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "2.0.0"

        // Enhanced device info matching standard LAN handshake
        let modelId = DeviceTypeUtil.modelIdentifier()
        let categoryTypeRaw = DeviceTypeUtil.deviceTypeDescription()
        let exactDeviceNameRaw = DeviceTypeUtil.deviceFullDescription()
        let categoryType = categoryTypeRaw.isEmpty ? "Mac" : categoryTypeRaw
        let exactDeviceName = exactDeviceNameRaw.isEmpty ? categoryType : exactDeviceNameRaw
        let savedAppPackages = Array(AppState.shared.androidApps.keys)

        let messageDict: [String: Any] = [
            "type": "macInfo",
            "data": [
                "name": macName,
                "isPlus": isPlusSubscription,
                "isPlusSubscription": isPlusSubscription, // Essential for Android check
                "version": appVersion,
                "model": modelId,
                "type": categoryType,
                "categoryType": categoryType,
                "exactDeviceName": exactDeviceName,
                "savedAppPackages": savedAppPackages
            ]
        ]

        if let jsonData = try? JSONSerialization.data(withJSONObject: messageDict),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            AirBridgeClient.shared.sendText(jsonString)
        }
    }

    /// Sends a wake signal through the relay so Android can attempt a LAN reconnect.
    func sendWakeViaRelay() {
        // Include current LAN endpoint hints so Android can reconnect without requiring a manual pair.
        // getLocalIPAddress(adapterName:nil) returns a comma-separated list in auto-mode.
        let adapter = AppState.shared.selectedNetworkAdapterName
        let lanAllowed = TrustedLANNetwork.shared.isAllowed
        let ipList = lanAllowed ? TrustedLANNetwork.shared.allowedAddresses.joined(separator: ",") : ""
        let port = Int(localPort ?? Defaults.serverPort)

        let messageDict: [String: Any] = [
            "type": "macWake",
            "data": [
                "ips": ipList,
                "lanAllowed": lanAllowed,
                "networkIDs": TrustedLANNetwork.shared.currentNetworkIDs,
                "port": port,
                "adapter": adapter ?? "auto"
            ]
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: messageDict),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            print("[airbridge] Failed to encode macWake message")
            return
        }

        AirBridgeClient.shared.sendText(jsonString)

        // Also emit a transport offer round so Android can immediately try LAN upgrade.
        if lanAllowed { sendTransportOffer(reason: "mac_wake") }
    }

    // MARK: - Crypto Helpers
    
    func loadOrGenerateSymmetricKey() {
        let defaults = UserDefaults.standard
        if let savedKey = defaults.string(forKey: "encryptionKey"),
           let keyData = Data(base64Encoded: savedKey) {
            symmetricKey = SymmetricKey(data: keyData)
        } else {
            let base64Key = generateSymmetricKey()
            defaults.set(base64Key, forKey: "encryptionKey")
            if let keyData = Data(base64Encoded: base64Key) {
                symmetricKey = SymmetricKey(data: keyData)
            }
        }
        TrustedLANNetwork.shared.refresh()
    }

    func resetSymmetricKey() {
        UserDefaults.standard.hasPairedDeviceOnce = false
        UserDefaults.standard.removeObject(forKey: "encryptionKey")
        loadOrGenerateSymmetricKey()
    }

    func getSymmetricKeyBase64() -> String? {
        guard let key = symmetricKey else { return nil }
        return key.withUnsafeBytes { Data($0).base64EncodedString() }
    }

    func setEncryptionKey(base64Key: String) {
        if let data = Data(base64Encoded: base64Key) {
            symmetricKey = SymmetricKey(data: data)
            UserDefaults.standard.set(base64Key, forKey: "encryptionKey")
            TrustedLANNetwork.shared.refresh()
        }
    }

    func wakeUpLastConnectedDevice() {
        QuickConnectManager.shared.wakeUpLastConnectedDevice()
    }

    // MARK: - Restart Helper

    /// Explicit configuration changes can restart the listener; transport loss cannot.
    func restartServer() {
        requestRestart(reason: "Explicit restart", delay: 1.5)
    }
}

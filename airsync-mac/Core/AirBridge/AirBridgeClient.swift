//
//  AirBridgeClient.swift
//  airsync-mac
//
//  Created by tornado-bunk and an AI Assistant.
//  WebSocket client that connects to a self-hosted AirBridge relay server.
//  When a direct LAN connection is unavailable, messages are tunneled through
//  the relay to reach the Android device.
//

import Foundation
import Combine
import CryptoKit
import AppKit
import Network
import OSLog

class AirBridgeClient: ObservableObject {
    static let shared = AirBridgeClient()
    static let credentialsDidChange = Foundation.Notification.Name("AirBridgeCredentialsDidChange")

    // MARK: - Published State

    @Published var connectionState: AirBridgeConnectionState = .disconnected
    @Published var isPeerConnected: Bool = false

    // Ping mechanism
    private var pingTimer: DispatchSourceTimer?
    private var lastPongReceived: Date = .distantPast
    private let pingInterval: TimeInterval = 8.0
    private let peerTimeout: TimeInterval = 20.0

    // MARK: - Configuration
    //
    // The secret is cached in memory after the first Keychain read so that
    // subsequent accesses never hit the Keychain again.

    private static let keychainKeySecret = "airBridgeSecret"

    // In-memory cache for the secret
    private var _cachedSecret: String?
    private var _secretLoaded = false

    /// Loads the secret from Keychain once
    private func loadSecretIfNeeded() {
        guard !_secretLoaded else { return }
        _secretLoaded = true

        // Current key
        if let s = KeychainStorage.string(for: Self.keychainKeySecret) {
            _cachedSecret = s
        }
    }

    var relayServerURL: String {
        get { UserDefaults.standard.string(forKey: "airBridgeRelayURL") ?? "" }
        set {
            UserDefaults.standard.set(newValue, forKey: "airBridgeRelayURL")
            NotificationCenter.default.post(name: Self.credentialsDidChange, object: nil)
        }
    }

    var pairingId: String {
        get { UserDefaults.standard.string(forKey: "airBridgePairingId") ?? "" }
        set {
            UserDefaults.standard.set(newValue, forKey: "airBridgePairingId")
            NotificationCenter.default.post(name: Self.credentialsDidChange, object: nil)
        }
    }

    var secret: String {
        get { loadSecretIfNeeded(); return _cachedSecret ?? "" }
        set {
            _cachedSecret = newValue
            _secretLoaded = true
            KeychainStorage.set(newValue, for: Self.keychainKeySecret)
            NotificationCenter.default.post(name: Self.credentialsDidChange, object: nil)
        }
    }

    /// Batch-update all three credentials.  Only the secret write touches Keychain
    func saveAllCredentials(url: String, pairingId: String, secret: String) {
        UserDefaults.standard.set(url, forKey: "airBridgeRelayURL")
        UserDefaults.standard.set(pairingId, forKey: "airBridgePairingId")
        _cachedSecret = secret
        _secretLoaded = true
        KeychainStorage.set(secret, for: Self.keychainKeySecret)
        NotificationCenter.default.post(name: Self.credentialsDidChange, object: nil)
    }

    /// Ensures pairing credentials exist, generating them if empty.
    /// Call this only when AirBridge is actually being enabled/configured.
    func ensureCredentialsExist() {
        if pairingId.isEmpty {
            pairingId = Self.generateShortId()
        }
        if secret.isEmpty {
            let newSecret = Self.generateRandomSecret()
            _cachedSecret = newSecret
            _secretLoaded = true
            KeychainStorage.set(newSecret, for: Self.keychainKeySecret)
        }
    }

    // MARK: - Private State

    private var webSocketTask: URLSessionWebSocketTask?
    private var urlSession: URLSession?
    private var reconnectAttempt: Int = 0
    private var maxReconnectDelay: TimeInterval = 30.0
    private var isManuallyDisconnected = false
    private var receiveLoopActive = false
    private let queue = DispatchQueue(label: "com.airsync.airbridge", qos: .userInitiated)
    private var connectionGeneration: Int = 0
    private var pendingReconnectWorkItem: DispatchWorkItem?
    private var networkMonitor: NWPathMonitor?
    private var lastNetworkRoute: NetworkRouteSnapshot?
    private var handshakeTimeoutWorkItem: DispatchWorkItem?
    private var relayPingTimeoutWorkItem: DispatchWorkItem?
    private let logger = Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff")

    private var relayProtocol: RelayProtocol?
    private var relayReady = false
    /// Tracks the nonce from the server's challenge message for HMAC computation
    private var pendingNonce: String?

    private init() {
        // Observe system wake events so we can notify Android via relay and trigger a LAN reconnect.
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.handleWakeFromSleep()
        }
    }

    // MARK: - Public Interface

    /// Connection mode gate. Reads the persisted mode directly from UserDefaults:
    /// `AppState.shared` may still be initializing (dispatch_once) when connect() is
    /// triggered from `AppState.init`, and touching it there would re-enter the
    /// once-token ("trying to lock recursively" crash).
    private func isRelayModePermitted() -> Bool {
        UserDefaults.standard.string(forKey: "appConnectionMode") == AppState.AppConnectionMode.dynamic.rawValue
    }

    /// Connects to the relay server. Does nothing if already connected, the URL is empty,
    /// or the current connection mode does not permit the relay (Dynamic only).
    func connect() {
        guard isRelayModePermitted() else {
            print("[airbridge] connect skipped: relay disabled in \(UserDefaults.standard.string(forKey: "appConnectionMode") ?? "unknown") mode")
            DispatchQueue.main.async { self.connectionState = .disconnected }
            return
        }
        queue.async { [weak self] in
            guard let self = self else { return }
            self.isManuallyDisconnected = false
            self.startNetworkMonitoring()
            guard !self.receiveLoopActive || self.webSocketTask == nil else { return }
            self.connectInternal()
        }
    }

    /// Gracefully disconnects from the relay server. Disables auto-reconnect.
    func disconnect() {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.isManuallyDisconnected = true
            self.networkMonitor?.cancel()
            self.networkMonitor = nil
            self.lastNetworkRoute = nil
            self.connectionGeneration += 1
            self.pendingReconnectWorkItem?.cancel()
            self.pendingReconnectWorkItem = nil
            self.tearDown(reason: "Manual disconnect")
            DispatchQueue.main.async {
                self.connectionState = .disconnected
            }
        }
    }

    /// All application messages pass through authenticated framing and encryption here.
    func sendText(_ text: String) {
        queue.async { [weak self] in
            guard let self, self.relayReady,
                  let frame = self.relayProtocol?.wrap(text) else { return }
            self.sendEncryptedFrame(frame)
        }
    }

    private func sendEncryptedFrame(_ frame: String) {
        guard let key = WebSocketServer.shared.symmetricKey,
              let encrypted = encryptMessage(frame, using: key),
              let task = webSocketTask else { return }
        let generation = connectionGeneration
        task.send(.string(encrypted)) { [weak self] error in
            guard error != nil, let self else { return }
            self.queue.async {
                self.scheduleReconnect(sourceGeneration: generation)
            }
        }
    }

    /// Tests connectivity to a relay server without affecting the live connection.
    ///
    /// Opens an isolated WebSocket, performs the 2-step HMAC challenge-response
    /// handshake, and considers success if the handshake completes without error.
    ///
    /// - Parameters:
    ///   - url:       Raw relay URL (will be normalised, same as `relayServerURL`).
    ///   - pairingId: Pairing ID to register with.
    ///   - secret:    Plain-text secret (will be SHA-256 hashed for HMAC).
    ///   - timeout:   Maximum seconds to wait (default 8 s).
    ///   - completion: Called on the **main thread** with `.success(())` or `.failure(error)`.
    func testConnectivity(
        url: String,
        pairingId: String,
        secret: String,
        timeout: TimeInterval = 8,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard let normalized = normalizeRelayURL(url), let wsURL = URL(string: normalized) else {
            DispatchQueue.main.async {
                completion(.failure(ConnectivityError.invalidURL(url)))
            }
            return
        }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        let session = URLSession(configuration: config)
        let task = session.webSocketTask(with: wsURL)
        task.resume()

        // Timer to enforce the overall timeout
        var settled = false
        let lock = NSLock()

        func settle(_ result: Result<Void, Error>) {
            lock.lock()
            let alreadyDone = settled
            settled = true
            lock.unlock()
            guard !alreadyDone else { return }
            task.cancel(with: .normalClosure, reason: nil)
            session.invalidateAndCancel()
            DispatchQueue.main.async { completion(result) }
        }

        // Schedule timeout
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            settle(.failure(ConnectivityError.timeout))
        }

        // Wait for challenge from server (step 1)
        task.receive { [weak self] result in
            guard self != nil else {
                settle(.failure(ConnectivityError.timeout))
                return
            }

            switch result {
            case .success(let message):
                guard case .string(let text) = message,
                      let data = text.data(using: .utf8),
                      let challengeMsg = try? JSONDecoder().decode(AirBridgeChallengeMessage.self, from: data),
                      challengeMsg.action == .challenge else {
                    settle(.failure(ConnectivityError.encodingFailed))
                    return
                }

                // Compute HMAC (step 2)
                let (sig, kInit) = Self.computeHMAC(secretRaw: secret, nonce: challengeMsg.nonce, pairingId: pairingId, role: "mac")

                let regMessage = AirBridgeRegisterMessage(
                    action: .register,
                    role: "mac",
                    pairingId: pairingId,
                    sig: sig,
                    kInit: kInit,
                    localIp: "0.0.0.0",
                    port: 0
                )

                guard let regData = try? JSONEncoder().encode(regMessage),
                      let regJSON = String(data: regData, encoding: .utf8) else {
                    settle(.failure(ConnectivityError.encodingFailed))
                    return
                }

                task.send(.string(regJSON)) { sendError in
                    if let sendError = sendError {
                        settle(.failure(sendError))
                    } else {
                        settle(.success(()))
                    }
                }

            case .failure(let error):
                settle(.failure(error))
            }
        }
    }

    // MARK: - Connectivity Error Types

    enum ConnectivityError: LocalizedError {
        case invalidURL(String)
        case timeout
        case encodingFailed

        var errorDescription: String? {
            switch self {
            case .invalidURL(let url): return "Invalid relay URL: \(url)"
            case .timeout:             return "Connection timed out. Check the server URL and your network."
            case .encodingFailed:      return "Failed to encode registration message."
            }
        }
    }

    /// Regenerates pairing credentials together so an ID and secret always stay in sync.
    /// PairingId goes to UserDefaults, secret to Keychain.
    func regeneratePairingCredentials() {
        pairingId = Self.generateShortId()
        let newSecret = Self.generateRandomSecret()
        _cachedSecret = newSecret
        _secretLoaded = true
        KeychainStorage.set(newSecret, for: Self.keychainKeySecret)
        NotificationCenter.default.post(name: Self.credentialsDidChange, object: nil)
    }

    /// Returns a `airbridge://` URI containing all pairing config, suitable for QR encoding.
    func generateQRCodeData() -> String {
        let urlEncoded = relayServerURL.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? relayServerURL
        return "airbridge://\(urlEncoded)/\(pairingId)/\(secret)"
    }

    // MARK: - HMAC Computation

    /// Computes the HMAC-SHA256 signature and kInit for challenge-response auth.
    /// - Parameters:
    ///   - secretRaw: The plain-text secret from Keychain
    ///   - nonce: The server-provided nonce from the challenge message
    ///   - pairingId: The pairing ID
    ///   - role: The client role ("mac" or "android")
    /// - Returns: Tuple of (sig, kInit) both hex-encoded
    static func computeHMAC(secretRaw: String, nonce: String, pairingId: String, role: String) -> (sig: String, kInit: String) {
        // K = SHA256(secret_raw) as raw bytes
        let kData = Data(SHA256.hash(data: Data(secretRaw.utf8)))
        let key = SymmetricKey(data: kData)

        // kInit = hex(K) — sent only for session bootstrap
        let kInit = kData.map { String(format: "%02x", $0) }.joined()

        // message = nonce|pairingId|role
        let message = "\(nonce)|\(pairingId)|\(role)"
        let mac = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: key)
        let sig = Data(mac).map { String(format: "%02x", $0) }.joined()

        return (sig, kInit)
    }

    // MARK: - Connection Logic

    private func connectInternal() {
        // Backstop: internal reconnect paths (wake, scheduleReconnect) must not bypass the mode gate.
        guard isRelayModePermitted() else {
            print("[airbridge] reconnect skipped: relay disabled in \(UserDefaults.standard.string(forKey: "appConnectionMode") ?? "unknown") mode")
            DispatchQueue.main.async { self.connectionState = .disconnected }
            return
        }

        guard !relayServerURL.isEmpty else {
            DispatchQueue.main.async { self.connectionState = .disconnected }
            return
        }

        guard !isManuallyDisconnected, lastNetworkRoute?.isReachable != false else { return }

        // Ensure credentials exist before connecting
        ensureCredentialsExist()

        // Normalize URL: ensure it ends with /ws and has wss:// or ws:// prefix
        guard let normalizedURL = normalizeRelayURL(relayServerURL),
              let url = URL(string: normalizedURL) else {
            print("[airbridge] Invalid relay URL")
            DispatchQueue.main.async { self.connectionState = .failed(error: "Invalid URL") }
            return
        }

        isManuallyDisconnected = false
        pendingReconnectWorkItem?.cancel()
        pendingReconnectWorkItem = nil
        pendingNonce = nil
        relayProtocol = nil
        relayReady = false
        connectionGeneration += 1
        let generation = connectionGeneration
        DispatchQueue.main.async { self.connectionState = .connecting }

        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        config.timeoutIntervalForRequest = 15

        urlSession = URLSession(configuration: config)
        webSocketTask = urlSession?.webSocketTask(with: url)
        webSocketTask?.resume()

        // Start receiving messages — the first message should be the challenge
        receiveLoopActive = true
        startReceiving(expectedGeneration: generation)
        armHandshakeTimeout(generation: generation)
        logger.info("Relay connecting, generation=\(generation)")
    }

    private func armHandshakeTimeout(generation: Int) {
        handshakeTimeoutWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, generation == self.connectionGeneration else { return }
            self.logger.notice("Relay handshake timed out")
            self.scheduleReconnect(sourceGeneration: generation)
        }
        handshakeTimeoutWorkItem = work
        queue.asyncAfter(deadline: .now() + 15, execute: work)
    }

    /// Handles the challenge message from the server and sends the HMAC register response.
    private func handleChallenge(nonce: String, expectedGeneration: Int) {
        guard expectedGeneration == connectionGeneration else { return }
        DispatchQueue.main.async { self.connectionState = .challengeReceived }

        let (sig, kInit) = Self.computeHMAC(secretRaw: secret, nonce: nonce, pairingId: pairingId, role: "mac")

        let localIP = WebSocketServer.shared.getLocalIPAddress(
            adapterName: AppState.shared.selectedNetworkAdapterName
        ) ?? "unknown"
        let port = Int(WebSocketServer.shared.localPort ?? Defaults.serverPort)

        let regMessage = AirBridgeRegisterMessage(
            action: .register,
            role: "mac",
            pairingId: pairingId,
            sig: sig,
            kInit: kInit,
            localIp: localIP,
            port: port
        )

        do {
            let data = try JSONEncoder().encode(regMessage)
            if let jsonString = String(data: data, encoding: .utf8) {
                DispatchQueue.main.async { self.connectionState = .registering }
                webSocketTask?.send(.string(jsonString)) { [weak self] error in
                    guard let self = self else { return }
                    self.queue.async {
                        guard expectedGeneration == self.connectionGeneration else { return }
                        if let error = error {
                            print("[airbridge] Registration send failed: \(error.localizedDescription)")
                            self.scheduleReconnect(sourceGeneration: expectedGeneration)
                        } else {
                            DispatchQueue.main.async {
                                self.connectionState = .waitingForPeer
                            }
                            self.handshakeTimeoutWorkItem?.cancel()
                            self.handshakeTimeoutWorkItem = nil
                            self.startPingLoop()
                        }
                    }
                }
            }
        } catch {
            print("[airbridge] Failed to encode registration: \(error)")
        }
    }

    // MARK: - Receive Loop

    private func startReceiving(expectedGeneration: Int) {
        guard receiveLoopActive, let task = webSocketTask else { return }

        task.receive { [weak self] result in
            guard let self = self else { return }
            self.queue.async {
                guard self.receiveLoopActive, expectedGeneration == self.connectionGeneration else { return }
                switch result {
                case .success(let message):
                    self.handleMessage(message, expectedGeneration: expectedGeneration)
                    // Continue receiving
                    self.startReceiving(expectedGeneration: expectedGeneration)
                case .failure(let error):
                    print("[airbridge] Receive error: \(error.localizedDescription)")
                    self.receiveLoopActive = false
                    self.scheduleReconnect(sourceGeneration: expectedGeneration)
                }
            }
        }
    }

    private func handleMessage(_ message: URLSessionWebSocketTask.Message, expectedGeneration: Int) {
        switch message {
        case .string(let text):
            handleTextMessage(text, expectedGeneration: expectedGeneration)
        case .data(let data):
            handleBinaryMessage(data)
        @unknown default:
            print("[airbridge] Unknown message type received")
        }
    }

    private func handleTextMessage(_ text: String, expectedGeneration: Int) {
        // First, try to parse as an AirBridge control message
        if let data = text.data(using: .utf8),
           let baseMsg = try? JSONDecoder().decode(AirBridgeBaseMessage.self, from: data) {

            switch baseMsg.action {
            case .challenge:
                // Server sent us a challenge — compute HMAC and respond with register
                if let challengeMsg = try? JSONDecoder().decode(AirBridgeChallengeMessage.self, from: data) {
                    handleChallenge(nonce: challengeMsg.nonce, expectedGeneration: expectedGeneration)
                } else {
                    print("[airbridge] Failed to decode challenge message")
                }
                return

            case .relayStarted:
                relayReady = false
                relayProtocol = RelayProtocol(role: "mac")
                DispatchQueue.main.async { self.connectionState = .waitingForPeer }
                sendEncryptedFrame(relayProtocol!.hello)
                armHandshakeTimeout(generation: expectedGeneration)
                return

            case .macInfo:
                // Server echoing our own info, ignore
                return

            case .error:
                if let errorMsg = try? JSONDecoder().decode(AirBridgeErrorMessage.self, from: data) {
                    print("[airbridge] Server error: \(errorMsg.message)")
                    DispatchQueue.main.async {
                        self.connectionState = .failed(error: errorMsg.message)
                    }
                }
                return

            default:
                break
            }
        }

        guard let key = WebSocketServer.shared.symmetricKey,
              let plaintext = decryptMessage(text, using: key),
              let relayProtocol else { return }
        let result = relayProtocol.receive(plaintext)
        if let reply = result.reply {
            sendEncryptedFrame(reply)
            if !relayReady {
                relayReady = true
                activateRelay()
            }
        }
        if let payload = result.payload, relayReady {
            WebSocketServer.shared.handleRelayedMessage(payload)
        }
    }

    private func activateRelay() {
        logger.info("Relay tunnel established")
        handshakeTimeoutWorkItem?.cancel()
        handshakeTimeoutWorkItem = nil
        pendingReconnectWorkItem?.cancel()
        pendingReconnectWorkItem = nil
        reconnectAttempt = 0
        DispatchQueue.main.async {
            self.connectionState = .relayActive
            WebSocketServer.shared.sendTrustedNetworkControl(TrustedLANNetwork.shared.catalog())
            // Fresh relay session: the peer may have restarted and its
            // transport generation counter starts over, so stale higher
            // generations must not block the next negotiation round.
            WebSocketServer.shared.resetTransportNegotiationState()
            if !WebSocketServer.shared.hasActiveLocalSession() {
                AppState.shared.updatePeerTransportHint("relay")
            }
            self.startPingLoop()
            if !WebSocketServer.shared.hasActiveLocalSession() {
                WebSocketServer.shared.sendPeerTransportStatus("relay")
            }
            WebSocketServer.shared.sendWakeViaRelay()
        }
    }

    private func handleBinaryMessage(_ data: Data) {
        // Binary data from the relay is currently unused in the AirSync protocol
        _ = data
    }

    private func startPingLoop() {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.pingTimer?.cancel()
            self.pingTimer = nil
            guard self.webSocketTask != nil else { return }
            self.lastPongReceived = Date()
            let generation = self.connectionGeneration

            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + self.pingInterval, repeating: self.pingInterval)
            timer.setEventHandler { [weak self] in
                guard let self = self else { return }

                let timeSinceLastPong = Date().timeIntervalSince(self.lastPongReceived)
                if self.relayReady && timeSinceLastPong > self.peerTimeout {
                    DispatchQueue.main.async {
                        if self.isPeerConnected {
                            print("[airbridge] Peer ping timeout (\(Int(timeSinceLastPong))s > \(Int(self.peerTimeout))s). Marking disconnected.")
                            self.isPeerConnected = false
                        }
                    }
                }

                guard generation == self.connectionGeneration, let task = self.webSocketTask else { return }
                // WebSocket pong checks the relay itself; application pong only checks the phone.
                let timeout = DispatchWorkItem { [weak self] in
                    guard let self else { return }
                    self.logger.notice("Relay WebSocket pong timed out")
                    self.scheduleReconnect(sourceGeneration: generation)
                }
                self.relayPingTimeoutWorkItem?.cancel()
                self.relayPingTimeoutWorkItem = timeout
                self.queue.asyncAfter(deadline: .now() + 6, execute: timeout)
                task.sendPing { [weak self] error in
                    guard let self else { return }
                    self.queue.async {
                        guard generation == self.connectionGeneration else { return }
                        self.relayPingTimeoutWorkItem?.cancel()
                        self.relayPingTimeoutWorkItem = nil
                        if error != nil { self.scheduleReconnect(sourceGeneration: generation) }
                    }
                }
                if self.relayReady { self.sendText("{\"type\":\"ping\"}") }
            }
            self.pingTimer = timer
            timer.resume()
        }
    }
    
    func processPong() {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.lastPongReceived = Date()
            DispatchQueue.main.async {
                self.isPeerConnected = true
            }
        }
    }

    private func startNetworkMonitoring() {
        guard networkMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self, weak monitor] path in
            guard let self, let monitor, self.networkMonitor === monitor else { return }
            let route = NetworkRouteSnapshot(path: path)
            guard route != self.lastNetworkRoute else { return }
            let previous = self.lastNetworkRoute
            self.lastNetworkRoute = route
            if previous == nil && route.isReachable && self.webSocketTask != nil { return }
            self.recoverAfterNetworkChange(reason: route.isReachable ? "Network route changed" : "Network unavailable")
        }
        networkMonitor = monitor
        monitor.start(queue: queue)
    }

    /// Recovery never overrides a user's disconnect or the selected connection mode.
    func recoverConnection(reason: String) {
        queue.async { [weak self] in
            guard let self, !self.isManuallyDisconnected, self.isRelayModePermitted(),
                  UserDefaults.standard.bool(forKey: "airBridgeEnabled"),
                  !UserDefaults.standard.isManuallyDisconnected else { return }
            self.startNetworkMonitoring()
            guard self.webSocketTask == nil, self.pendingReconnectWorkItem == nil else { return }
            self.connectInternal()
        }
    }

    private func recoverAfterNetworkChange(reason: String) {
        guard networkMonitor != nil, !isManuallyDisconnected, isRelayModePermitted(),
              !UserDefaults.standard.isManuallyDisconnected else { return }
        connectionGeneration += 1
        pendingReconnectWorkItem?.cancel()
        pendingReconnectWorkItem = nil
        tearDown(reason: reason)
        reconnectAttempt = 0
        logger.notice("\(reason, privacy: .public); network available=\(self.lastNetworkRoute?.isReachable ?? false)")
        guard lastNetworkRoute?.isReachable != false else {
            DispatchQueue.main.async { self.connectionState = .disconnected }
            return
        }
        DispatchQueue.main.async { self.connectionState = .connecting }
        let generation = connectionGeneration
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.isManuallyDisconnected, generation == self.connectionGeneration else { return }
            self.connectInternal()
        }
        pendingReconnectWorkItem = work
        queue.asyncAfter(deadline: .now() + 1, execute: work)
    }

    private func handleWakeFromSleep() {
        queue.async { [weak self] in
            guard let self else { return }
            self.recoverAfterNetworkChange(reason: "System wake")
        }
        DispatchQueue.main.async { WebSocketServer.shared.checkNetworkChange() }
    }

    // MARK: - Reconnect

    private func scheduleReconnect(sourceGeneration: Int) {
        guard !isManuallyDisconnected else { return }
        guard sourceGeneration == connectionGeneration else {
            return
        }

        // Invalidate all other callbacks from this failed socket before tearing it down.
        connectionGeneration += 1
        let retryGeneration = connectionGeneration
        tearDown(reason: "Preparing reconnect")
        guard lastNetworkRoute?.isReachable != false else { return }

        let delay = min(pow(2.0, Double(reconnectAttempt)), maxReconnectDelay)
        reconnectAttempt += 1

        DispatchQueue.main.async {
            self.connectionState = .connecting
        }

        pendingReconnectWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            guard !self.isManuallyDisconnected, retryGeneration == self.connectionGeneration else { return }
            self.connectInternal()
        }
        pendingReconnectWorkItem = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func tearDown(reason: String) {
        handshakeTimeoutWorkItem?.cancel()
        handshakeTimeoutWorkItem = nil
        relayPingTimeoutWorkItem?.cancel()
        relayPingTimeoutWorkItem = nil
        relayProtocol = nil
        relayReady = false
        receiveLoopActive = false
        pendingNonce = nil
        webSocketTask?.cancel(with: .goingAway, reason: reason.data(using: .utf8))
        webSocketTask = nil
        urlSession?.invalidateAndCancel()
        urlSession = nil
        
        pingTimer?.cancel()
        pingTimer = nil
        DispatchQueue.main.async { self.isPeerConnected = false }
    }

    // MARK: - Helpers

    private func normalizeRelayURL(_ raw: String) -> String? {
        RelayUrlPolicy.normalize(raw)
    }

    /// Generates a 32-char lowercase hex ID (128-bit entropy)
    static func generateShortId() -> String {
        var bytes = [UInt8](repeating: 0, count: 16) // 16 bytes = 128 bits
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Generates a cryptographically strong secret token (192-bit / 48 hex chars)
    /// formatted as 8 groups of 6 chars for readability (e.g. "a3f8b2-c1e9d0-471f8a-2b3c4d-5e6f78-90abcd-ef1234-567890")
    static func generateRandomSecret() -> String {
        var bytes = [UInt8](repeating: 0, count: 24) // 24 bytes = 192 bits
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        // Split into 8 groups of 6 chars for readability
        var groups: [String] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let end = hex.index(idx, offsetBy: 6, limitedBy: hex.endIndex) ?? hex.endIndex
            groups.append(String(hex[idx..<end]))
            idx = end
        }
        return groups.joined(separator: "-")
    }
}

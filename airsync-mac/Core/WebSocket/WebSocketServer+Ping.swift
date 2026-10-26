//
//  WebSocketServer+Ping.swift
//  airsync-mac
//

import Foundation
import Swifter
import OSLog

extension WebSocketServer {
    
    // MARK: - Heartbeat / Ping
    
    func startPing() {
        DispatchQueue.main.async {
            self.stopPing()
            self.lock.lock()
            let interval = self.pingInterval
            self.lock.unlock()
            
            self.pingTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
                self?.performPing()
            }
            self.pingTimer?.tolerance = 0.5
        }
    }
    
    func stopPing() {
        self.lock.lock()
        pingTimer?.invalidate()
        pingTimer = nil
        self.lock.unlock()
    }
    
    /// Expire stale sessions without restarting a healthy listening socket.
    func performPing() {
        self.lock.lock()
        let sessions = activeSessions
        let timeout = self.activityTimeout
        let key = self.symmetricKey
        let primary = self.primarySessionID
        self.lock.unlock()
        
        if sessions.isEmpty { return }
        
        let now = Date()
        
        // We use a local copy of sessions to avoid prolonged locking during network I/O
        for session in sessions {
            let sessionId = ObjectIdentifier(session)
            
            self.lock.lock()
            let lastDate = self.lastActivity[sessionId] ?? .distantPast
            self.lock.unlock()
            
            let timeSinceLastActivity = now.timeIntervalSince(lastDate)
            let isStale = timeSinceLastActivity > timeout
            
            let isPrimary = (sessionId == primary)
            if isPrimary && !isStale {
                let isWeak = timeSinceLastActivity > 12
                DispatchQueue.main.async {
                    if AppState.shared.isConnectionWeak != isWeak {
                        AppState.shared.isConnectionWeak = isWeak
                        if isWeak {
                            print("[websocket] Primary session connection is weak. Time since last activity: \(Int(timeSinceLastActivity))s")
                        } else {
                            print("[websocket] Primary session connection recovered.")
                        }
                    }
                }
            }
            
            if isStale {
                removeLocalSession(session, reason: "heartbeat_timeout")
                session.socket.close()
                continue
            }

            let pingJson = "{\"type\":\"ping\",\"data\":{}}"
            
            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self = self else { return }
                self.lock.lock()
                defer { self.lock.unlock() }
                guard self.activeSessions.contains(where: { $0 === session }) else { return }
                if let key = key, let encrypted = encryptMessage(pingJson, using: key) {
                    session.writeText(encrypted)
                } else {
                    session.writeText(pingJson)
                }
            }
        }
    }

    /// Shared by socket callbacks, heartbeat expiry and local-address loss.
    func removeLocalSession(_ session: WebSocketSession, reason: String) {
        lock.lock()
        let id = ObjectIdentifier(session)
        guard activeSessions.contains(where: { $0 === session }) else {
            lock.unlock()
            return
        }
        activeSessions.removeAll(where: { $0 === session })
        lastActivity.removeValue(forKey: id)
        sessionLocalAddresses.removeValue(forKey: id)
        sessionNetworkIDs.removeValue(forKey: id)
        sessionProofNonces.removeValue(forKey: id)
        let wasPrimary = primarySessionID == id
        if wasPrimary { primarySessionID = nil }
        let empty = activeSessions.isEmpty
        lock.unlock()
        if empty {
            MacRemoteManager.shared.stopVolumeMonitoring()
            stopPing()
        }
        guard wasPrimary else { return }
        Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff")
            .notice("LAN session ended: \(reason, privacy: .public)")
        publishLanTransportState(isActive: false, reason: reason)
        AirBridgeClient.shared.recoverConnection(reason: reason)
        DispatchQueue.main.async {
            guard !self.hasActiveLocalSession() else { return }
            AppState.shared.isConnectionWeak = false
            ADBConnector.disconnectADB()
            AppState.shared.adbConnected = false
            if AirBridgeClient.shared.connectionState == .relayActive {
                AppState.shared.updatePeerTransportHint("relay")
                self.sendWakeViaRelay()
            } else if !BLECentralManager.shared.isAuthenticated {
                AppState.shared.disconnectDevice(manual: false, unlessReconnected: true)
            }
        }
    }

}

//
//  WebSocketServer+Networking.swift
//  airsync-mac
//

import Foundation
import UniformTypeIdentifiers
import Network
import OSLog
import Swifter
#if canImport(MobileCoreServices)
import MobileCoreServices
#endif

extension WebSocketServer {
    
    // MARK: - Local IP handling

    /// Retrieves the local IP address based on configuration.
    /// Supports binding to a specific adapter or auto-discovery of all available non-loopback interfaces.
    func getLocalIPAddress(adapterName: String?) -> String? {
        let adapters = getAvailableNetworkAdapters()

        if let adapterName = adapterName {
            if let exact = adapters.first(where: { $0.name == adapterName }) {
                self.lock.lock()
                let lastLogged = lastLoggedSelectedAdapter
                self.lock.unlock()
                
                if lastLogged?.name != exact.name || lastLogged?.address != exact.address {
                    print("[websocket] Selected adapter match: \(exact.name) -> \(exact.address)")
                    self.lock.lock()
                    lastLoggedSelectedAdapter = (exact.name, exact.address)
                    self.lock.unlock()
                }
                return exact.address
            }
        }

        // Auto mode
        if adapterName == nil {
            let allAddresses = adapters.map { $0.address }
            if !allAddresses.isEmpty {
                let joined = allAddresses.joined(separator: ",")
                
                self.lock.lock()
                let lastLogged = lastLoggedSelectedAdapter
                self.lock.unlock()
                
                if lastLogged?.address != joined {
                    print("[websocket] Auto-mode addresses: \(joined)")
                    self.lock.lock()
                    lastLoggedSelectedAdapter = ("auto", joined)
                    self.lock.unlock()
                }
                return joined
            }
        }

        return nil
    }

    func getAvailableNetworkAdapters() -> [(name: String, address: String)] {
        var adapters: [(String, String)] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>? = nil

        if getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr {
            for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
                let interface = ptr.pointee
                guard let address = interface.ifa_addr,
                      interface.ifa_flags & UInt32(IFF_UP) != 0,
                      interface.ifa_flags & UInt32(IFF_RUNNING) != 0,
                      interface.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
                let addrFamily = address.pointee.sa_family

                if addrFamily == UInt8(AF_INET),
                   let name = String(validatingUTF8: interface.ifa_name) {
                    var addr = interface.ifa_addr.pointee
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let result = getnameinfo(&addr,
                                             socklen_t(interface.ifa_addr.pointee.sa_len),
                                             &hostname,
                                             socklen_t(hostname.count),
                                             nil,
                                             socklen_t(0),
                                             NI_NUMERICHOST)
                    if result == 0 {
                        let address = String(cString: hostname)
                        if address != "127.0.0.1" {
                            adapters.append((name, address))
                        }
                    }
                }
            }
            freeifaddrs(ifaddr)
        }
        return adapters.sorted { ($0.0, $0.1) < ($1.0, $1.1) }
    }

    func ipIsPrivatePreferred(_ ip: String) -> Bool {
        if ip.hasPrefix("192.168.") { return true }
        if ip.hasPrefix("10.") { return true }
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count > 1, let second = Int(parts[1]), (16...31).contains(second) {
                return true
            }
        }
        return false
    }

    // MARK: - Network Monitoring

    func startNetworkMonitoring() {
        stopNetworkMonitoring()
        let monitor = NWPathMonitor()
        networkPathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self, weak monitor] _ in
            DispatchQueue.main.async {
                guard let self, let monitor, self.networkPathMonitor === monitor else { return }
                self.pendingNetworkChangeWorkItem?.cancel()
                let work = DispatchWorkItem { [weak self] in self?.checkNetworkChange() }
                self.pendingNetworkChangeWorkItem = work
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: work)
            }
        }
        monitor.start(queue: networkMonitorQueue)
        // Address changes do not always produce a default-path change.
        networkMonitorTimer = Timer.scheduledTimer(withTimeInterval: networkCheckInterval, repeats: true) { [weak self] _ in
            self?.checkNetworkChange()
        }
        networkMonitorTimer?.tolerance = 1
    }

    func stopNetworkMonitoring() {
        networkPathMonitor?.cancel()
        networkPathMonitor = nil
        pendingNetworkChangeWorkItem?.cancel()
        pendingNetworkChangeWorkItem = nil
        networkMonitorTimer?.invalidate()
        networkMonitorTimer = nil
    }

    /// Refresh discovery and relay hints without dropping the wildcard listener.
    func checkNetworkChange() {
        lock.lock()
        let listening = !servers.isEmpty
        lock.unlock()
        guard listening else { return }
        TrustedLANNetwork.shared.refresh()
        let lanAllowed = TrustedLANNetwork.shared.isAllowed
        let networkIDs = Set(TrustedLANNetwork.shared.currentNetworkIDs)
        let policyChanged = lanAllowed != lastTrustedLANAllowed || networkIDs != lastTrustedLANNetworkIDs
        lastTrustedLANAllowed = lanAllowed
        lastTrustedLANNetworkIDs = networkIDs
        let adapters = getAvailableNetworkAdapters()
        let previousAddresses = Set(lastKnownAdapters.map { $0.address })
        AppState.shared.revalidateNetworkAdapter()
        let chosenIP = getLocalIPAddress(adapterName: AppState.shared.selectedNetworkAdapterName)
        let addresses = Set(adapters.map { $0.address })
        guard addresses != previousAddresses || chosenIP != lastKnownIP || policyChanged else { return }

        // Preserve sessions if an unrelated adapter was added or removed.
        let lostPreviousNetwork = !previousAddresses.isEmpty && previousAddresses.isDisjoint(with: addresses)
        lastKnownAdapters = adapters
        lastKnownIP = chosenIP
        localIPAddress = chosenIP
        if let port = localPort {
            AppState.shared.webSocketStatus = .started(port: port, ip: chosenIP)
        }
        AppState.shared.shouldRefreshQR = true
        Logger(subsystem: "sameerasw.airsync-mac", category: "NetworkHandoff")
            .notice("Local addresses changed; available=\(addresses.count), previous network lost=\(lostPreviousNetwork)")
        lock.lock()
        let sessions = activeSessions.filter {
            if !lanAllowed { return true }
            if let address = sessionLocalAddresses[ObjectIdentifier($0)] {
                guard let networkID = sessionNetworkIDs[ObjectIdentifier($0)] else { return !addresses.contains(address) }
                return !addresses.contains(address) || !TrustedLANNetwork.shared.allows(networkID: networkID, localAddress: address)
            }
            return lostPreviousNetwork
        }
        lock.unlock()
        for session in sessions {
            removeLocalSession(session, reason: "local_network_lost")
            session.socket.close()
        }
        DiscoveryManager.shared.broadcastBurst()
        AirBridgeClient.shared.recoverConnection(reason: "Local addresses changed")
        sendWakeViaRelay()
    }

    // MARK: - Utils

    func mimeType(for url: URL) -> String? {
        let ext = url.pathExtension
        if ext.isEmpty { return nil }

        if #available(macOS 11.0, *) {
            if let ut = UTType(filenameExtension: ext) {
                return ut.preferredMIMEType
            }
        } else {
#if canImport(MobileCoreServices)
            if let uti = UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, ext as CFString, nil)?.takeRetainedValue() {
                if let mime = UTTypeCopyPreferredTagWithClass(uti, kUTTagClassMIMEType)?.takeRetainedValue() as String? {
                    return mime
                }
            }
#endif
        }
        return nil
    }
}

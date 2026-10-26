import Foundation
import Swifter

extension WebSocketServer {
    func sendTrustedNetworkControl(_ data: [String: Any], session: WebSocketSession? = nil) {
        guard let encoded = try? JSONSerialization.data(withJSONObject: ["type": "trustedNetworks", "data": data]),
              let text = String(data: encoded, encoding: .utf8) else { return }
        if let session {
            guard let key = symmetricKey, let encrypted = encryptMessage(text, using: key) else { return }
            session.writeText(encrypted)
        } else {
            AirBridgeClient.shared.sendText(text)
            lock.lock()
            let local = activeSessions.first { ObjectIdentifier($0) == primarySessionID }
            lock.unlock()
            if let local, let key = symmetricKey, let encrypted = encryptMessage(text, using: key) { local.writeText(encrypted) }
        }
    }

    func handleTrustedNetworkControl(_ message: Message, session: WebSocketSession?) {
        guard let data = message.data.value as? [String: Any], let op = data["op"] as? String else { return }
        if op == "proof" {
            guard let session, let nonce = data["nonce"] as? String, UUID(uuidString: nonce) != nil,
                  let peer = try? session.socket.peername() else { return }
            let peerAddress = peer.hasPrefix("::ffff:") ? String(peer.dropFirst(7)) : peer
            guard let network = TrustedLANNetwork.shared.verifyProof(data, peerAddress: peerAddress) else {
                sendTrustedNetworkControl(["op": "rejected", "nonce": nonce, "reason": "This network is not authorized. Add it in Trusted networks with both devices connected locally."], session: session)
                removeLocalSession(session, reason: "network_not_authorized")
                session.socket.close()
                return
            }
            lock.lock()
            sessionNetworkIDs[ObjectIdentifier(session)] = network.id
            sessionProofNonces[ObjectIdentifier(session)] = nonce
            sessionLocalAddresses[ObjectIdentifier(session)] = data["target"] as? String
            lock.unlock()
            sendTrustedNetworkControl(["op": "accepted", "nonce": nonce, "networkID": network.id, "catalog": TrustedLANNetwork.shared.catalog()], session: session)
            sendTrustedNetworkControl(TrustedLANNetwork.shared.catalog())
            sendWakeViaRelay()
            return
        }
        if let session {
            lock.lock()
            let authorized = sessionNetworkIDs[ObjectIdentifier(session)] != nil
            lock.unlock()
            guard authorized else { return }
        }
        switch op {
        case "catalog":
            TrustedLANNetwork.shared.merge(data)
            checkNetworkChange()
        case "enrollmentFailed":
            guard let requestID = data["requestID"] as? String else { return }
            TrustedLANNetwork.shared.failEnrollment(requestID: requestID)
        case "enrollmentFinished":
            guard let requestID = data["requestID"] as? String, let networkID = data["networkID"] as? String else { return }
            TrustedLANNetwork.shared.finishKnownEnrollment(requestID: requestID, networkID: networkID)
        case "requestEnrollment":
            guard let requestID = data["requestID"] as? String, let name = data["name"] as? String else { return }
            TrustedLANNetwork.shared.prepareEnrollment(requestID: requestID, name: name)
        default: break
        }
    }
}

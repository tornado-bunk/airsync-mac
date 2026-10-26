import Foundation
import Swifter

// Link against the real Swifter build: the unit socket double cannot expose sockaddr truncation.
let server = HttpServer()
server.listenAddressIPv4 = "127.0.0.1"
server["/peer"] = { request in .ok(.text(request.address ?? "missing")) }
try server.start(0, forceIPv4: true)
defer { server.stop() }
let port = try server.port()
let finished = DispatchSemaphore(value: 0)
URLSession.shared.dataTask(with: URL(string: "http://127.0.0.1:\(port)/peer")!) { data, _, error in
    precondition(error == nil, "Real LAN listener request failed")
    precondition(data.flatMap { String(data: $0, encoding: .utf8) } == "127.0.0.1", "Swifter must return the actual IPv4 peer")
    finished.signal()
}.resume()
precondition(finished.wait(timeout: .now() + 10) == .success, "Real LAN listener timed out")
print("PASS: real Swifter listener preserves IPv4 peer identity")

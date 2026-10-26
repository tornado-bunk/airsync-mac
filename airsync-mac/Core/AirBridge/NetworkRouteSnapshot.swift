import Foundation
import Network

/// Tracks the preferred route, without reconnecting for changes to unrelated adapters.
nonisolated struct NetworkRouteSnapshot: Equatable {
    let isReachable: Bool
    let interfaceName: String?
    let addresses: Set<String>
    let gateways: Set<String>

    init(path: NWPath) {
        isReachable = path.status == .satisfied
        interfaceName = path.availableInterfaces.first?.name
        gateways = Set(path.gateways.map { String(describing: $0) })
        var result = Set<String>()
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&interfaces) == 0, let first = interfaces {
            defer { freeifaddrs(interfaces) }
            for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
                let entry = pointer.pointee
                guard String(cString: entry.ifa_name) == interfaceName,
                      let address = entry.ifa_addr,
                      address.pointee.sa_family == UInt8(AF_INET) || address.pointee.sa_family == UInt8(AF_INET6) else { continue }
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    result.insert(String(cString: host))
                }
            }
        }
        addresses = result
    }
}

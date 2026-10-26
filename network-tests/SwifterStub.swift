// Socket doubles used only by the session-lifecycle regression harness.
public final class Socket {
    public private(set) var closed = false
    public init() {}
    public func close() { closed = true }
}
public final class WebSocketSession {
    public let socket = Socket()
    public private(set) var messages: [String] = []
    public init() {}
    public func writeText(_ text: String) { messages.append(text) }
}

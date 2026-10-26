import Foundation

let a = String(repeating: "a", count: 32)
let b = String(repeating: "b", count: 32)
let mac = RelayProtocol(role: "mac", nonce: a)
let android = RelayProtocol(role: "android", nonce: b)
precondition(mac.wrap("not ready") == nil)
precondition(mac.hello == "AB1|hello|mac|\(a)")
precondition(mac.receive(android.hello).reply == mac.hello)
precondition(android.receive(mac.hello).reply == android.hello)
precondition(mac.receive(android.hello).reply == nil)
let payload = "{\"type\":\"clipboardUpdate\",\"data\":{\"text\":\"caffè|☕\"}}"
let frame = mac.wrap(payload)!
precondition(frame == "AB1|data|mac|\(a)|\(b)|1|\(payload)")
precondition(android.receive(frame).payload == payload)
precondition(android.receive(frame).payload == nil)
_ = android.receive(mac.hello)
precondition(android.receive(frame).payload == nil) // A replayed hello cannot reset counters.
precondition(mac.receive(frame).payload == nil) // Reflection.
let second = mac.wrap("two")!
let third = mac.wrap("three")!
precondition(android.receive(third).payload == "three")
precondition(android.receive(second).payload == nil) // Reordering cannot re-execute an old command.
let fresh = RelayProtocol(role: "android", nonce: String(repeating: "c", count: 32))
_ = fresh.receive(mac.hello)
precondition(fresh.receive(frame).payload == nil) // Reconnect/restart, even with a replayed hello.
precondition(fresh.receive(payload).payload == nil) // Legacy frames fail closed.
precondition(fresh.receive("AB1|hello|mac|bad").reply == nil)
let reverse = android.wrap("reply")!
precondition(mac.receive(reverse).payload == "reply")

precondition(RelayUrlPolicy.normalize("relay.example.com") == "wss://relay.example.com/ws")
precondition(RelayUrlPolicy.normalize("ws://10.relay.example.com") == "wss://10.relay.example.com/ws")
precondition(RelayUrlPolicy.normalize("ws://192.168.relay.example.com") == "wss://192.168.relay.example.com/ws")
precondition(RelayUrlPolicy.normalize("ws://10.0.0.2:8080") == "ws://10.0.0.2:8080/ws")
precondition(RelayUrlPolicy.normalize("ws://172.31.1.2") == "ws://172.31.1.2/ws")
precondition(RelayUrlPolicy.normalize("ws://172.32.1.2") == "wss://172.32.1.2/ws")
precondition(!RelayUrlPolicy.isPrivateHost("10.0.0.999"))
precondition(!RelayUrlPolicy.isPrivateHost("010.0.0.1"))
precondition(RelayUrlPolicy.normalize("ws://user@relay.example.com") == nil)
precondition(RelayUrlPolicy.normalize("https://relay.example.com") == nil)
precondition(RelayUrlPolicy.normalize("wss://relay.example.com/ws?key=x") == nil)
precondition(RelayUrlPolicy.normalize("wss://relay.example.com:0") == nil)
print("Swift AirBridge security checks passed")

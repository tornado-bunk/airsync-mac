# AirBridge regression checks

AB1 is an incompatible relay application format: update Mac and Android together.
The Go relay does not need a protocol change. BLE framing is unchanged.
The updated LAN clients require authenticated trusted-network verification.

`main.swift` exercises the production framing and URL policy without app dependencies.
Compile it with both `airsync-mac/Core/AirBridge/RelayProtocol.swift` and
`airsync-mac/Core/AirBridge/RelayUrlPolicy.swift` in an isolated macOS CI job, then run
the resulting executable. No dependencies or network access are needed.

The Kotlin checks use the same wire-format fixture, including Unicode and `|` inside
JSON. They cover bidirectional frames, reflection, duplicate data, replayed hello,
out-of-order messages, a fresh receiver session, legacy rejection, and URL validation.

## Integration verification

- Update both apps; pair using dummy devices/keys. Verify relay sync and ping/pong,
  LAN upgrade, reconnect, and peer restart. A legacy client must not activate AB1.
- Using a disposable local relay fixture, replay an encrypted application frame in
  the same session and after reconnect. Verify the command executes only once.
- Send `browseLs`, `refreshAdbPorts`, and `startQuickShare` over relay, both with and
  without a simultaneous LAN connection. Android must reject them; the Mac relay
  router must not acquire LAN file-transfer permissions.
- Remove the encryption key in a fixture: no application plaintext may reach relay.

These isolated checks complement full app builds and device integration tests.
They do not replace end-to-end replay and transport-isolation testing with real
encryption and a disposable peer.

# Network handoff regressions

Run `python3 network-tests/run.py` from the Mac repository on macOS with Xcode command-line tools.

The harness compiles production `AirBridgeClient`, framing/URL policy, trusted-network models/store and LAN session expiry code. It uses a local WebSocket fixture plus isolated UI, Keychain and socket doubles. The first connection withholds the relay challenge; subsequent connections test socket interruption and missing WebSocket pong while application pong still arrives. Manual disconnect must cancel scheduled wake recovery.

The pairing tests exercise source-address/subnet checks, first enrollment, guest and overlapping-subnet rejection, explicit additional registration, DHCP changes, catalog conflict resolution and key isolation. ARP parsing fixtures verify that Ethernet and Wi-Fi share a router identity and VPN interfaces are excluded.

Encryption functions are identity doubles **in this harness only**, so this suite does not validate production encryption, platform permissions, actual Wi-Fi/Ethernet routing or physical guest-network isolation. The app build uses its real encryption. Framing and URL-policy checks also live in `security-tests/`.

The shared catalog uses random IDs and Lamport revisions with deterministic role tie-breaking. A tombstone always wins over an offline rename; adding again creates a new ID. Observations are scoped to the pairing key and never hardcode a user's network. Mac recognition combines gateway MAC, gateway IP and subnet; Android combines Wi-Fi name/security family, gateway IP and subnet. Local proof is mandatory and cannot be supplied through the relay.

Known boundaries: recognition currently requires IPv4 and a discoverable gateway; uncertain observations use Airbridge. It is a conservative network-recognition mechanism, not cryptographic attestation of the router hardware. Replacing the router requires registration again. Background Android recognition requires the appropriate location permission; force-stopping the app prevents background automation until it is reopened.

ICE generation checks run with `python3 network-tests/transport-generation.py`.
They compile the production server negotiation methods and verify fresh offers,
delayed answers, monotonic counters, validation, and relay-session reset.
The Android `TransportGenerationTest` exercises the corresponding production methods.

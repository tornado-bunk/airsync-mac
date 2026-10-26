#!/usr/bin/env python3
"""Exercise the actual server's negotiation methods without starting the app UI."""
import pathlib
import subprocess
import tempfile
root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'airsync-mac/Core/WebSocket/WebSocketServer.swift').read_text()
methods = source[source.index('    internal func nextTransportGeneration'):source.index('    /// Configures WebSocket routes')]
fixture = '''import Foundation
final class Round {
 let lock = NSRecursiveLock()
 var transportGenerationCounter: Int64 = 0
 var activeTransportGeneration: Int64 = 0
 var activeTransportGenerationStartedAt: Date?
 var validatedTransportGeneration: Int64 = 0
 let transportGenerationTTL: TimeInterval = 120
''' + methods + '''
}
let round = Round()
let first = round.nextTransportGeneration()
round.beginTransportRound(first, reason: "local_offer")
precondition(round.acceptIncomingTransportGeneration(first + 1, reason: "new_offer"))
precondition(!round.acceptIncomingTransportGeneration(first, reason: "delayed_answer"))
precondition(round.nextTransportGeneration() == first + 2)
round.markTransportGenerationValidated(first + 1, reason: "check_ack")
precondition(round.isTransportGenerationValidated(first + 1))
precondition(round.acceptIncomingTransportGeneration(first + 3, reason: "next_offer"))
precondition(!round.isTransportGenerationValidated(first + 3))
round.resetTransportNegotiationState()
precondition(round.nextTransportGeneration() == 1)
precondition(round.acceptIncomingTransportGeneration(1, reason: "peer_restarted"))
precondition(!round.acceptIncomingTransportGeneration(0, reason: "invalid"))
print("PASS: ICE fresh offers, delayed answers, monotonic counters, validation and relay reset")
'''
with tempfile.TemporaryDirectory(prefix='airsync-ice-') as directory:
    path = pathlib.Path(directory)
    (path / 'main.swift').write_text(fixture)
    subprocess.run(['swiftc', '-module-cache-path', str(path / 'cache'), str(path / 'main.swift'), '-o', str(path / 'checks')], check=True)
    subprocess.run([str(path / 'checks')], check=True)

#!/usr/bin/env python3
"""Compile production lifecycle code with isolated UI/socket/crypto doubles and a local WS fixture."""
import base64
import hashlib
import json
import pathlib
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def read_frame(conn):
    header = read_exact(conn, 2)
    size = header[1] & 127
    if size == 126:
        size = struct.unpack("!H", read_exact(conn, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", read_exact(conn, 8))[0]
    if size > 1024 * 1024:
        raise ValueError("oversized fixture frame")
    mask = read_exact(conn, 4) if header[1] & 128 else None
    payload = read_exact(conn, size)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header[0] & 15, payload


def send_frame(conn, payload, opcode=1):
    if isinstance(payload, str):
        payload = payload.encode()
    size = len(payload)
    length = bytes([size]) if size < 126 else bytes([126]) + struct.pack("!H", size)
    conn.sendall(bytes([128 | opcode]) + length + payload)


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    opened = 0
    count_lock = threading.Lock()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(35)
        try:
            request = b""
            while b"\r\n\r\n" not in request:
                request += read_exact(conn, 1)
                if len(request) > 8192:
                    return
            headers = dict(line.split(":", 1) for line in request.decode().split("\r\n")[1:] if ":" in line)
            key = next(value.strip() for key, value in headers.items() if key.lower() == "sec-websocket-key")
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode())
            with self.server.count_lock:
                self.server.opened += 1
                number = self.server.opened
            if number == 1:
                # TCP/WebSocket are live, but the relay never sends its auth challenge.
                while conn.recv(4096):
                    pass
                return
            send_frame(conn, json.dumps({"action": "challenge", "nonce": "fixture-challenge"}))
            opcode, payload = read_frame(conn)
            if opcode != 1 or json.loads(payload).get("action") != "register":
                return
            send_frame(conn, json.dumps({"action": "relay_started"}))
            android_nonce = uuid.uuid4().hex
            mac_nonce = None
            sequence = 0
            drop_pongs = False
            while True:
                opcode, payload = read_frame(conn)
                if opcode == 8:
                    send_frame(conn, payload, 8)
                    return
                if opcode == 9:
                    if not drop_pongs:
                        send_frame(conn, payload, 10)
                    continue
                if opcode != 1:
                    continue
                parts = payload.decode().split("|", 6)
                if len(parts) == 4 and parts[:3] == ["AB1", "hello", "mac"]:
                    if mac_nonce is None:
                        mac_nonce = parts[3]
                        send_frame(conn, "AB1|hello|android|" + android_nonce)
                elif len(parts) == 7 and parts[:3] == ["AB1", "data", "mac"]:
                    message = json.loads(parts[6])
                    if message.get("type") == "testClose":
                        return
                    if message.get("type") == "testDropWebSocketPongs":
                        drop_pongs = True
                    if message.get("type") == "ping":
                        sequence += 1
                        send_frame(conn, f'AB1|data|android|{android_nonce}|{mac_nonce}|{sequence}|{{"type":"pong"}}')
        except (OSError, EOFError, ValueError, StopIteration):
            pass


def main():
    with tempfile.TemporaryDirectory(prefix="airsync-network-tests-") as tmp:
        tmp = pathlib.Path(tmp)
        common = ["xcrun", "swiftc", "-module-cache-path", str(tmp / "module-cache")]
        subprocess.run(common + ["-emit-library", "-emit-module", "-module-name", "Swifter", str(ROOT / "network-tests/SwifterStub.swift"), "-o", str(tmp / "libSwifter.dylib")], check=True)
        sources = [
            "network-tests/Stubs.swift", "network-tests/main.swift",
            "airsync-mac/Core/AirBridge/AirBridgeClient.swift",
            "airsync-mac/Core/AirBridge/AirBridgeModels.swift",
            "airsync-mac/Core/AirBridge/RelayProtocol.swift",
            "airsync-mac/Core/AirBridge/RelayUrlPolicy.swift",
            "airsync-mac/Core/AirBridge/NetworkRouteSnapshot.swift",
            "airsync-mac/Core/AirBridge/TrustedNetwork.swift",
            "airsync-mac/Core/AirBridge/TrustedLANNetwork.swift",
            "airsync-mac/Core/WebSocket/WebSocketServer+Ping.swift",
        ]
        subprocess.run(common + ["-I", str(tmp), "-L", str(tmp), "-lSwifter", "-Xlinker", "-rpath", "-Xlinker", str(tmp)] + [str(ROOT / source) for source in sources] + ["-o", str(tmp / "checks")], check=True)
        with Relay(("127.0.0.1", 0), Handler) as relay:
            thread = threading.Thread(target=relay.serve_forever, daemon=True)
            thread.start()
            try:
                subprocess.run([str(tmp / "checks"), str(relay.server_address[1])], check=True, timeout=65)
            finally:
                relay.shutdown()


if __name__ == "__main__":
    main()

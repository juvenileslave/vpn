#!/usr/bin/env python3
"""Disposable real network payload endpoints/client; no mocked proxy protocol."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise OSError("truncated network transfer")
        result.extend(part)
    return bytes(result)


def socks(port, address, target):
    sock = socket.create_connection(("127.0.0.1", port), timeout=30)
    sock.sendall(b"\x05\x01\x00")
    if exact(sock, 2) != b"\x05\x00":
        raise OSError("SOCKS authentication failed")
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(address) + struct.pack("!H", target))
    head = exact(sock, 4)
    if head[1] != 0:
        sock.close()
        raise OSError("SOCKS path denied")
    if head[3] == 1:
        exact(sock, 6)
    elif head[3] == 4:
        exact(sock, 18)
    else:
        exact(sock, exact(sock, 1)[0] + 2)
    return sock


def transfer(port, size, address="192.0.2.100", target=18080):
    data = (bytes(range(256)) * ((size + 255) // 256))[:size]
    flow = secrets.token_bytes(16)
    digest = hashlib.sha256(data).hexdigest()
    start = time.monotonic()
    with socks(port, address, target) as sock:
        sock.sendall(flow + struct.pack("!I", size))
        # Full-duplex reader prevents echo backpressure from serial send/recv.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            receiving = pool.submit(exact, sock, size)
            sock.sendall(data)
            returned = receiving.result(timeout=180)
        if hashlib.sha256(returned).hexdigest() != digest:
            raise AssertionError("bidirectional integrity mismatch")
        # The sink's measured receipt is written before this acknowledgement.
        if exact(sock, 16) != flow:
            raise AssertionError("application flow acknowledgement mismatch")
    return {"flow_id": flow.hex(), "payload_sha256": digest, "bytes_each_direction": size, "seconds": time.monotonic() - start}


def load(ports):
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as pool:
        futures = [pool.submit(transfer, port, 262144) for port in ports for _ in range(4)]
        results = [job.result(timeout=240) for job in futures]
    seconds = time.monotonic() - start
    latency = sorted(item["seconds"] for item in results)
    return {"users": len(ports), "flows_per_user": 4, "flows": len(results), "bytes_each_direction": sum(item["bytes_each_direction"] for item in results), "seconds": seconds, "bidirectional_mbit_s": 2 * sum(item["bytes_each_direction"] for item in results) * 8 / seconds / 1e6, "flow_latency_seconds_p50": latency[len(latency) // 2], "flow_latency_seconds_p95": latency[int(len(latency) * .95) - 1]}


def serve(logfile):
    lock = threading.Lock()

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(180)
            flow = exact(self.request, 16)
            size = struct.unpack("!I", exact(self.request, 4))[0]
            remaining = size
            digest = hashlib.sha256()
            while remaining:
                part = self.request.recv(min(65536, remaining))
                if not part:
                    raise OSError("truncated upload")
                digest.update(part)
                self.request.sendall(part)
                remaining -= len(part)
            with lock:
                with open(logfile, "a") as output:
                    output.write(json.dumps({"source": self.client_address[0], "port": self.client_address[1], "flow_id": flow.hex(), "bytes_each_direction": size, "payload_sha256": digest.hexdigest()}) + "\n")
            self.request.sendall(flow)

    class HTTP(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    class TCP(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    echo = TCP(("0.0.0.0", 18080), Echo)
    probe = ThreadingHTTPServer(("0.0.0.0", 18081), HTTP)
    threading.Thread(target=probe.serve_forever, daemon=True).start()
    echo.serve_forever()


if __name__ == "__main__":
    from runtime_vm import guard_identity
    guard_identity()
    if sys.argv[1] == "serve":
        serve(sys.argv[2])
    elif sys.argv[1] == "load":
        print(json.dumps(load([int(p) for p in sys.argv[2:]])))
    elif sys.argv[1] == "transfer":
        print(json.dumps(transfer(int(sys.argv[2]), int(sys.argv[3]), *(sys.argv[4:5]), *([int(sys.argv[5])] if len(sys.argv) > 5 else []))))

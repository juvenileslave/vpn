"""Real dual-stack listeners and packet clients for the disposable base scenario."""

from __future__ import annotations

import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import threading
import time

PAYLOAD = bytes(range(256)) * 4096
PAYLOAD_DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/peer":
            address = ipaddress.ip_address(self.client_address[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            payload = json.dumps({"source": str(address)}).encode()
        else:
            payload = PAYLOAD
        if self.path == "/pmtu":
            peer = ipaddress.ip_address(self.client_address[0])
            # Linux UAPI: force DF / IPv6 PMTU discovery only for this real
            # disposable transition, never rely on black-hole fallback.
            if isinstance(peer, ipaddress.IPv4Address) or peer.ipv4_mapped is not None:
                self.connection.setsockopt(socket.IPPROTO_IP, 10, 2)
            else:
                self.connection.setsockopt(socket.IPPROTO_IPV6, 23, 2)
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


class DualStackHTTP(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def serve(tcp_ports, udp_port):
    for port in tcp_ports:
        server = DualStackHTTP(("::", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    serve_udp(udp_port)


def serve_udp(udp_port):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        udp.bind(("::", udp_port))
        while True:
            payload, peer = udp.recvfrom(4096)
            udp.sendto(payload, peer)


def request(address, port, path, expected_peer, source_address=None, control=None):
    source = (source_address, 0) if source_address is not None else None
    connection = http.client.HTTPConnection(address, port, timeout=10, source_address=source)
    try:
        connection.connect()
        if control is not None:
            ready, release = map(Path, control)
            ready.write_text(json.dumps({"source": connection.sock.getsockname(),
                                         "peer": connection.sock.getpeername(),
                                         "mss": connection.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)}))
            deadline = time.monotonic() + 10
            while not release.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("PMTU transition was not released")
                time.sleep(0.02)
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        payload = response.read()
        assert response.status == 200, response.status
        if path == "/peer":
            assert json.loads(payload)["source"] == expected_peer, "unexpected egress source"
        else:
            assert hashlib.sha256(payload).hexdigest() == PAYLOAD_DIGEST, "incomplete transfer"
    finally:
        connection.close()


def udp_request(address, port, source_address=None, source_port=0):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    destination = socket.getaddrinfo(address, port, family, socket.SOCK_DGRAM)[0][4]
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        if source_address is not None or source_port:
            source = source_address or ("::" if family == socket.AF_INET6 else "0.0.0.0")
            binding = socket.getaddrinfo(source, source_port, family, socket.SOCK_DGRAM)[0][4]
            client.bind(binding)
        payload = b"vpn-base-disposable-udp"
        client.sendto(payload, destination)
        received, _peer = client.recvfrom(4096)
        assert received == payload, "unexpected UDP response"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--tcp", nargs="+", required=True, type=int)
    server.add_argument("--udp", required=True, type=int)
    udp_server = sub.add_parser("serve-udp")
    udp_server.add_argument("port", type=int)
    for operation in ("get", "peer", "udp", "staged-get"):
        client = sub.add_parser(operation)
        client.add_argument("address")
        client.add_argument("port", type=int)
        if operation == "peer":
            client.add_argument("expected_peer")
        client.add_argument("--source-address")
        if operation == "udp":
            client.add_argument("--source-port", type=int, default=0)
        if operation == "staged-get":
            client.add_argument("ready")
            client.add_argument("release")
    args = parser.parse_args()
    if args.operation == "serve":
        serve(args.tcp, args.udp)
    elif args.operation == "serve-udp":
        serve_udp(args.port)
    elif args.operation == "udp":
        udp_request(args.address, args.port, args.source_address, args.source_port)
    else:
        path = "/peer" if args.operation == "peer" else "/pmtu" if args.operation == "staged-get" else "/payload"
        control = (args.ready, args.release) if args.operation == "staged-get" else None
        request(args.address, args.port, path, getattr(args, "expected_peer", None),
                args.source_address, control)


if __name__ == "__main__":
    main()

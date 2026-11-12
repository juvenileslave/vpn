#!/usr/bin/env python3
"""Probe real origin behaviour and prove it does not contact a loopback upstream."""
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading

ca, hostname, port, page = sys.argv[1:]
port = int(port)
context = ssl.create_default_context(cafile=ca)
context.set_alpn_protocols(['http/1.1'])
connections = []
observed = threading.Condition()

class Canary(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'private-upstream-must-not-be-reached')

    def log_message(self, *args):
        pass

class CountingServer(http.server.ThreadingHTTPServer):
    def get_request(self):
        accepted, address = super().get_request()
        with observed:
            connections.append(address)
            observed.notify_all()
        return accepted, address


canary = CountingServer(('127.0.0.1', 19091), Canary)
thread = threading.Thread(target=canary.serve_forever, daemon=True)
thread.start()

def probe(request, sni=hostname):
    if sni != hostname:
        # Authenticate the owned certificate hostname independently of the SNI
        # being probed. Never disable chain or hostname verification.
        argv = ['openssl', 's_client', '-quiet', '-connect', f'127.0.0.1:{port}',
                '-CAfile', ca, '-verify_return_error', '-verify_hostname', hostname,
                '-alpn', 'http/1.1']
        argv += ['-noservername'] if sni is None else ['-servername', sni]
        result = subprocess.run(argv, input=request.encode(), capture_output=True, timeout=5)
        assert result.returncode == 0, result.stderr.decode()
        data = result.stdout
        return int(data.split(b' ', 2)[1]), data.split(b'\r\n\r\n', 1)[1]
    with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            tls.settimeout(3)
            certificate = tls.getpeercert()
            assert certificate['subjectAltName'] == (('DNS', hostname),), certificate
            tls.sendall(request.encode())
            data = b''
            while chunk := tls.recv(65536):
                data += chunk
    status = int(data.split(b' ', 2)[1])
    return status, data.split(b'\r\n\r\n', 1)[1]

try:
    # A real direct connection must be observed before negative origin probes.
    with socket.create_connection(('127.0.0.1', 19091), timeout=3):
        with observed:
            assert observed.wait_for(lambda: len(connections) == 1, timeout=3), 'Canary missed its positive TCP control'
    with observed:
        connections.clear()
    get = f'GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
    assert probe(get, sni=None) == (200, Path(page).read_bytes())
    assert probe(get, sni='unknown.example.test') == (200, Path(page).read_bytes())
    verified = ssl.create_default_context(cafile=ca)
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
            verified.wrap_socket(raw, server_hostname='unknown.example.test')
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError('Unknown-name certificate unexpectedly verifies')
    missing_host, _ = probe('GET / HTTP/1.1\r\nConnection: close\r\n\r\n')
    assert missing_host == 400, missing_host
    absolute, body = probe(f'GET http://127.0.0.1:19091/ HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n')
    assert absolute == 200 and body == Path(page).read_bytes(), absolute
    connect, _ = probe(f'CONNECT 127.0.0.1:19091 HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n')
    assert connect >= 400, connect
    # Give the accept loop a bounded observation window after both responses.
    with observed:
        assert not observed.wait_for(lambda: bool(connections), timeout=0.5), connections
        upstream_connections = len(connections)
    print(json.dumps({'missing_sni': 200, 'unknown_sni': 200, 'unknown_sni_hostname_verification': 'fails', 'missing_host': missing_host, 'absolute_form': absolute, 'connect': connect, 'upstream_connections': upstream_connections}, sort_keys=True))
finally:
    canary.shutdown()
    canary.server_close()

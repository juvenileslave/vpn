#!/usr/bin/env python3
"""Real disposable RemnaNode/Xray/nginx/source-ACL acceptance, never production."""
from __future__ import annotations
import base64
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import yaml

from fixtures import ROOT, bundle, inputs, secret_strings

HERE = Path(__file__).resolve().parent


def imported(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NODE = ROOT / "ansible/roles/remnawave_node"
LIFE = None
PKI = None


class PrerequisiteError(RuntimeError):
    """Public-safe missing accepted-role gate; never a runtime success."""


def runtime_contracts():
    global LIFE, PKI
    required = (("#50", ROOT / "ansible/roles/cover_site/tasks/main.yml"), ("#51", NODE / "files/lifecycle.py"), ("#51", NODE / "tests/runtime_vm.py"), ("#49", ROOT / "ansible/roles/base/tasks/firewall.yml"))
    for pr, path in required:
        if not path.is_file():
            raise PrerequisiteError("required accepted PR " + pr + ": " + str(path.relative_to(ROOT)))
    LIFE = imported("node_life", NODE / "files/lifecycle.py")
    PKI = imported("node_fixture", NODE / "tests/runtime_vm.py")


def proxy_pump(left, right):
    peers = [left, right]
    while True:
        readable, _, _ = select.select(peers, [], [], 30)
        if not readable:
            return
        for source in readable:
            try:
                data = source.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                (right if source is left else left).sendall(data)
            except OSError:
                return


def proxy_session(client):
    with client:
        try:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                part = client.recv(4096)
                if not part or len(request) > 65536:
                    return
                request.extend(part)
            head, _, pending = bytes(request).partition(b"\r\n\r\n")
            method, target, _ = head.split(b"\r\n", 1)[0].decode("latin1").split(" ", 2)
            if method != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            host, _, port = target.rpartition(":")
            with socket.create_connection((host.strip("[]"), int(port)), timeout=30) as upstream:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if pending:
                    upstream.sendall(pending)
                proxy_pump(client, upstream)
        except (OSError, ValueError):
            return


def connect_proxy(address, port):
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((address, port))
        server.listen(32)
        while True:
            client, _peer = server.accept()
            threading.Thread(target=proxy_session, args=(client,), daemon=True).start()


def command(args, *, expected=True, env=None, timeout=600, combined=False):
    result = subprocess.run([str(x) for x in args], capture_output=True, env=env, timeout=timeout, check=False)
    if (result.returncode == 0) != expected:
        raise AssertionError("unexpected result: " + Path(str(args[0])).name + " (private output withheld)")
    return result.stdout + result.stderr if combined else result.stdout


def private_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True))
    path.chmod(0o600)


def guard():
    wanted = {"VPN_PROFILES_DISPOSABLE_GUEST": "yes", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    if os.geteuid() != 0 or any(os.environ.get(k) != v for k, v in wanted.items()) or sys.platform != "linux":
        raise SystemExit("refusing non-disposable profile runtime")
    for path in ("/etc/cover-site", "/var/lib/cover-site", "/etc/nginx/sites-enabled/cover-site.conf"):
        if Path(path).exists() or Path(path).is_symlink():
            raise SystemExit("fresh role-owned cover state required")


def wire_bytes(field, value):
    def varint(n):
        data = bytearray()
        while n > 127:
            data.append((n & 127) | 128)
            n >>= 7
        data.append(n)
        return bytes(data)
    return varint((field << 3) | 2) + varint(len(value)) + value


def fixture_geoip(path):
    # Real Xray protobuf fixture keeps RFC1918/ULA/link-local/loopback blocked;
    # only documentation-range test endpoints are not in PRIVATE. Production
    # retains stock geodata and identical routing/finalRules. No fake core.
    entry = wire_bytes(1, b"PRIVATE")
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"):
        net = ipaddress.ip_network(cidr)
        record = wire_bytes(1, net.network_address.packed) + b"\x10" + bytes([net.prefixlen])
        if net.prefixlen == 128:
            record = wire_bytes(1, net.network_address.packed) + b"\x10\x80\x01"
        entry += wire_bytes(2, record)
    path.write_bytes(wire_bytes(1, entry))
    path.chmod(0o600)


def captured_streams(decoded):
    """Count unique TCP payload sequence bytes, excluding SYNs/retransmits."""
    streams = {}
    pattern = re.compile(r"IP6? (\S+) > (\S+): .*seq (\d+):(\d+).*length (\d+)")
    for line in decoded.decode().splitlines():
        match = pattern.search(line)
        if match is None:
            continue
        source, destination, first, last, length = match.groups()
        first, last, length = int(first), int(last), int(length)
        if last < first:
            last += 2**32
        if length and last - first == length:
            streams.setdefault((source, destination), []).append((first, last))
    counts = {}
    for peers, intervals in streams.items():
        total, end = 0, -1
        for first, last in sorted(intervals):
            total += max(0, last - max(first, end))
            end = max(end, last)
        counts[peers] = total
    return counts


def established_pair(samples, source, destination):
    def endpoint(value):
        address, port = value.rsplit(".", 1)
        return address + ":" + port
    left, right = endpoint(source), endpoint(destination)
    for sample in samples:
        for line in sample.decode().splitlines():
            columns = [item.replace("[", "").replace("]", "") for item in line.split()]
            if left in columns and right in columns:
                return True
    return False


class Lab:
    def __init__(self, directory):
        self.work = directory
        self.prefix = "vp47-" + secrets.token_hex(3)
        self.namespaces = {}
        self.processes = []
        self.client_processes = {}
        self.evidence = {"schema": 1, "environment": "guarded-disposable-ubuntu-24.04", "node_image": bundle.NODE_IMAGE, "core_version": bundle.CORE_VERSION, "scenarios": {}}
        self.old_hosts = Path("/etc/hosts").read_bytes()
        self.output = directory / "bundles"
        self.topology, self.secret = inputs(20)
        self.topology["profiles_probe_url"] = "http://192.0.2.100:18081/generate_204"
        for kind in ("exit", "relay"):
            host = self.topology[kind]
            host["reality_sni"] = "cover.example.test"
            host["cover_tls_port"] = 18445
            host["cover_site_source"] = str(self.work / "site")
            host["cover_acme_email"] = "operator@example.test"
            host["node_port_allow"] = ["127.0.0.1/32", "::1/128"]
            host["base_firewall_source_ports"] = [{"proto": "tcp", "port": 2222, "source_cidrs": host["node_port_allow"]}]
            host["public_ipv4"] = "192.0.2.10" if kind == "exit" else "192.0.2.20"
            host["public_ipv6"] = "2001:db8:47::10" if kind == "exit" else "2001:db8:47::20"
        self.topology["exit"].update(exit_direct_port=18443, transit_port=18444, base_firewall_vpn_ports=[{"proto": "tcp", "port": 80}, {"proto": "tcp", "port": 18443}])
        self.topology["exit"]["base_firewall_source_ports"].append({"proto": "tcp", "port": 18444, "source_cidrs": ["192.0.2.20/32", "2001:db8:47::20/128"]})
        self.topology["relay"].update(relay_egress_ipv4="192.0.2.20", relay_egress_ipv6="2001:db8:47::20", relay_slot_ports=[19443, 19444, 19445], base_firewall_vpn_ports=[{"proto": "tcp", "port": p} for p in (80, 19443, 19444, 19445)])
        self.secret["relay_client_ids"] += [str(uuid.uuid4()), str(uuid.uuid4())]
        self.secret["profiles_user_slots"] += [1, 2]
        self.secret["profiles_upstreams"] = {"1": {"protocol": "socks", "settings": {"servers": [{"address": "192.0.2.50", "port": 18082}]}}}
        self.node_inputs = {}
        self.relay_env = None

    def ns(self, kind):
        return self.namespaces.get(kind)

    def run(self, kind, args, **kwargs):
        ns = self.ns(kind)
        return command((["ip", "netns", "exec", ns] if ns else []) + [str(x) for x in args], **kwargs)

    def spawn(self, kind, args, name, env=None, *, network_only=False):
        ns = self.ns(kind)
        prefix = ["nsenter", "--net=/run/netns/" + ns] if ns and network_only else ["ip", "netns", "exec", ns] if ns else []
        output = (self.work / (name + ".private.log")).open("wb")
        process = subprocess.Popen(prefix + [str(x) for x in args], stdout=output, stderr=subprocess.STDOUT, env=env)
        output.close()
        self.processes.append(process)
        return process

    def play(self, roles, kind="exit", variables=None, *, expected=True, check=False):
        inventory = self.work / "deployment-inventory.yml"
        wrapper = self.work / "relay-python"
        wrapper.write_text('#!/bin/sh\nexec ip netns exec ' + self.ns("relay") + ' /usr/bin/python3 "$@"\n')
        wrapper.chmod(0o700)
        inventory.write_text(yaml.safe_dump({"all": {"hosts": {"exit": {"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3"}, "relay": {"ansible_connection": "local", "ansible_python_interpreter": str(wrapper)}}}}))
        play = [{"name": "Disposable integration", "hosts": kind, "gather_facts": True, "environment": {"DOCKER_HOST": self.relay_env["DOCKER_HOST"]} if kind == "relay" and self.relay_env else {}, "tasks": [{"ansible.builtin.include_role": role if isinstance(role, dict) else {"name": str(ROOT / "ansible/roles" / role)}} for role in roles]}]
        path = self.work / "deployment-play.yml"
        path.write_text(yaml.safe_dump(play))
        varfile = self.work / "deployment-vars.private.json"
        private_json(varfile, variables or {})
        result = subprocess.run([str(ROOT / ".venv/bin/ansible-playbook"), "-i", str(inventory), str(path), "-e", "@" + str(varfile), *(["--check"] if check else [])], capture_output=True, timeout=600, check=False)
        if (result.returncode == 0) != expected:
            approved = set()
            def task_names(tasks):
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    name = task.get("name")
                    if isinstance(name, str) and "{{" not in name:
                        approved.add(name)
                    for section in ("block", "rescue", "always"):
                        task_names(task.get(section, []))
            for role in roles:
                directory = Path(role["name"]) if isinstance(role, dict) else ROOT / "ansible/roles" / role
                for definition in (directory / "tasks").glob("*.yml"):
                    task_names(yaml.safe_load(definition.read_text()) or [])
            failed_task = None
            failed_tasks = []
            current = None
            for line in result.stdout.decode(errors="replace").splitlines():
                match = re.match(r"^TASK \[(.*)\]", line)
                if match:
                    current = match.group(1).split(" : ", 1)[-1]
                    continue
                if current is not None and ("FAILED! =>" in line or line.startswith("fatal:")):
                    if current in approved and current not in failed_tasks:
                        failed_tasks.append(current)
                        if failed_task is None:
                            failed_task = current
            if failed_tasks:
                self.evidence["public_failed_role_tasks"] = failed_tasks[:5]
            if failed_task is not None:
                self.evidence["public_failed_role_task"] = failed_task
            if failed_task == "Bootstrap HTTP-01 without configuring nonexistent TLS files":
                # This step precedes certificate issuance/Node credentials and
                # emits only the controlled lifecycle's constraint, not vars.
                for line in result.stdout.decode(errors="replace").splitlines():
                    marker = line.find("FAILED! => ")
                    if marker < 0:
                        continue
                    try:
                        details = json.loads(line[marker + len("FAILED! => "):])
                    except json.JSONDecodeError:
                        continue
                    first = str(details.get("stderr", "")).splitlines()
                    if first and first[0].startswith("cover_site: "):
                        self.evidence["public_bootstrap_constraint"] = first[0]
            raise AssertionError("role execution failed; private values withheld")
        return result.stdout

    def render(self, topology=None, secret=None, *, expected=True):
        topology, secret = topology or self.topology, secret or self.secret
        inv = self.work / "profiles-inventory.yml"
        inv.write_text(yaml.safe_dump({"all": {"vars": {k: v for k, v in topology.items() if k not in ("exit", "relay")}, "children": {k: {"hosts": {k: topology[k]}} for k in ("exit", "relay")}}}))
        varsfile = self.work / "profiles-vars.private.json"
        private_json(varsfile, {**secret, "profiles_output_dir": str(self.output)})
        result = command([ROOT / ".venv/bin/ansible-playbook", "-i", inv, ROOT / "ansible/playbooks/profiles.yml", "-e", "@" + str(varsfile)], expected=expected)
        for value in secret_strings(secret):
            if value.encode() in result:
                raise AssertionError("secret leaked in profile output")
        if expected:
            return (self.output / "candidate").resolve(), result
        return None, result

    def network(self):
        bridge = self.prefix + "br"
        command(["ip", "link", "add", bridge, "type", "bridge"])
        command(["ip", "addr", "add", "192.0.2.10/24", "dev", bridge])
        command(["ip", "-6", "addr", "add", "2001:db8:47::10/64", "dev", bridge, "nodad"])
        command(["ip", "link", "set", bridge, "up"])
        for kind, suffix in (("relay", 20), ("client", 30), ("outsider", 40), ("upstream", 50), ("sink", 100)):
            ns = self.prefix + "-" + kind
            self.namespaces[kind] = ns
            command(["ip", "netns", "add", ns])
            interface = self.prefix + str(suffix)
            command(["ip", "link", "add", interface, "type", "veth", "peer", "name", "eth0", "netns", ns])
            command(["ip", "link", "set", interface, "master", bridge])
            command(["ip", "link", "set", interface, "up"])
            command(["ip", "-n", ns, "link", "set", "lo", "up"])
            command(["ip", "-n", ns, "link", "set", "eth0", "up"])
            command(["ip", "-n", ns, "addr", "add", f"192.0.2.{suffix}/24", "dev", "eth0"])
            command(["ip", "-n", ns, "-6", "addr", "add", f"2001:db8:47::{suffix}/64", "dev", "eth0", "nodad"])
        # No default route in any network namespace: no public-network traffic.
        Path("/etc/hosts").write_bytes(self.old_hosts + b"\n192.0.2.10 cover.example.test\n2001:db8:47::10 cover.example.test\n")

    def prerequisites(self):
        self.stage = "accepted-docker-installation"
        self.play(["docker"], variables={"docker_allow_version_change": True})
        existing = subprocess.run(["docker", "inspect", "vpn-remnanode"], capture_output=True, check=False)
        if existing.returncode == 0:
            raise AssertionError("fresh guest required; refusing an existing Node container")
        self.stage = "verified-embedded-core-extraction"
        command(["docker", "pull", "--quiet", bundle.NODE_IMAGE])
        extract = self.prefix + "-extract"
        command(["docker", "create", "--name", extract, "--network=none", "--entrypoint=sleep", bundle.NODE_IMAGE, "3600"])
        self.extract = extract
        self.assets = self.work / "core"
        self.assets.mkdir(mode=0o700)
        for name, source in (("xray", "/usr/local/bin/xray"), ("geoip.dat", "/usr/local/share/xray/geoip.dat"), ("geosite.dat", "/usr/local/share/xray/geosite.dat")):
            command(["docker", "cp", extract + ":" + source, self.assets / name])
        self.xray = self.assets / "xray"
        self.xray.chmod(0o700)
        if not command([self.xray, "version"]).startswith(b"Xray 26.11.9 "):
            raise AssertionError("embedded core version differs from verified pin")
        self.evidence["embedded_core_sha256"] = hashlib.sha256(self.xray.read_bytes()).hexdigest()
        self.evidence["stock_geoip_sha256"] = hashlib.sha256((self.assets / "geoip.dat").read_bytes()).hexdigest()
        self.stage = "disposable-geodata-fixture"
        fixture_geoip(self.assets / "geoip.dat")
        self.evidence["fixture_geoip_sha256"] = hashlib.sha256((self.assets / "geoip.dat").read_bytes()).hexdigest()
        self.core_env = {**os.environ, "XRAY_LOCATION_ASSET": str(self.assets)}
        self.stage = "pinned-reality-probe-build"
        build = self.work / "reality-probe-source"
        shutil.copytree(HERE / "reality_probe", build)
        self.probe_binary = self.work / "reality-probe"
        # Build from a copied private directory; never modify the checkout/go.sum.
        result = subprocess.run(["go", "build", "-mod=readonly", "-o", str(self.probe_binary), "."], cwd=build, env={**os.environ, "GOTOOLCHAIN": "auto", "GOWORK": "off"}, capture_output=True, timeout=900, check=False)
        if result.returncode:
            # Compiler input contains public source/dependencies only, no PKI.
            self.evidence["public_build_error"] = result.stderr.decode(errors="replace")
            self.evidence["public_go_version"] = command(["go", "version"]).decode().strip()
            raise AssertionError("pinned disposable REALITY probe build failed")
        self.stage = "pinned-local-acme-tool-build"
        command(["go", "install", "github.com/letsencrypt/pebble/v2/cmd/pebble@v2.6.0"], env={**os.environ, "GOBIN": str(self.work / "bin"), "GOTOOLCHAIN": "auto"}, timeout=900)

    def relay_daemon(self):
        data = self.work / "relay-docker"
        data.mkdir(mode=0o700)
        endpoint = "unix://" + str(data / "docker.sock")
        self.relay_env = {**os.environ, "DOCKER_HOST": endpoint}
        containerd_socket = data / "containerd.sock"
        containerd_config = data / "containerd.toml"
        containerd_config.write_text('version = 3\ndisabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n')
        containerd_config.chmod(0o600)
        runtime = self.spawn("relay", ["containerd", "--config", containerd_config, "--address", containerd_socket, "--root", data / "containerd-data", "--state", data / "containerd-state"], "relay-containerd", network_only=True)
        self.stage = "isolated-relay-containerd"
        for _ in range(30):
            if runtime.poll() is not None:
                self.evidence["public_containerd_startup_error"] = (self.work / "relay-containerd.private.log").read_text(errors="replace")
                raise AssertionError("private relay containerd exited before readiness")
            ready = subprocess.run(["ctr", "--address", str(containerd_socket), "version"], capture_output=True, check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            self.evidence["public_containerd_startup_error"] = (self.work / "relay-containerd.private.log").read_text(errors="replace")
            raise AssertionError("private relay containerd did not become ready")
        private_json(data / "daemon.json", {})
        self.stage = "isolated-relay-image-proxy"
        self.proxy = self.spawn("exit", [ROOT / ".venv/bin/python", __file__, "connect-proxy", "192.0.2.10", "3128"], "relay-image-proxy")
        for _ in range(60):
            if self.proxy.poll() is not None:
                raise AssertionError("loopback image proxy exited before readiness")
            if self.run("relay", [ROOT / ".venv/bin/python", __file__, "tcp", "192.0.2.10", "3128"]).strip() == b"open":
                break
            time.sleep(.1)
        else:
            raise AssertionError("loopback image proxy not ready")
        proxy_env = {**os.environ, "HTTPS_PROXY": "http://192.0.2.10:3128", "HTTP_PROXY": "http://192.0.2.10:3128", "NO_PROXY": "localhost,127.0.0.1,::1"}
        self.stage = "isolated-relay-docker-daemon"
        daemon = self.spawn("relay", ["dockerd", "--config-file", data / "daemon.json", "--host", endpoint, "--containerd", containerd_socket, "--data-root", data / "data", "--exec-root", data / "exec", "--pidfile", data / "pid", "--bridge=none", "--iptables=false", "--ip6tables=false", "--ip-forward=false", "--storage-driver=vfs"], "relay-docker", env=proxy_env, network_only=True)
        for _ in range(90):
            if daemon.poll() is not None:
                # No Node/container PKI has been loaded into this daemon yet.
                self.evidence["public_daemon_startup_error"] = (self.work / "relay-docker.private.log").read_text(errors="replace")
                raise AssertionError("isolated relay Docker daemon exited before API readiness")
            result = subprocess.run(["docker", "info"], env=self.relay_env, capture_output=True, check=False)
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            self.evidence["public_daemon_startup_error"] = (self.work / "relay-docker.private.log").read_text(errors="replace")
            raise AssertionError("isolated relay Docker daemon not ready")
        namespace = Path("/run/netns/" + self.ns("relay")).stat().st_ino
        assert Path("/proc/" + str(runtime.pid) + "/ns/net").stat().st_ino == namespace, "containerd is outside relay host-network namespace"
        assert Path("/proc/" + str(daemon.pid) + "/ns/net").stat().st_ino == namespace, "dockerd is outside relay host-network namespace"
        assert Path("/proc/self/ns/net").stat().st_ino != namespace, "relay runtime shares exit network namespace"
        self.evidence["relay_runtime_isolation"] = {"private_containerd": True, "daemon_and_containerd_same_relay_netns": True, "distinct_from_exit": True}
        self.stage = "isolated-relay-image-pull"
        command(["docker", "pull", "--quiet", bundle.NODE_IMAGE], env=self.relay_env, timeout=900)
        loaded = subprocess.run(["docker", "image", "inspect", bundle.NODE_IMAGE], env=self.relay_env, capture_output=True, check=False)
        if loaded.returncode != 0:
            self.evidence["public_relay_image_inspect_error"] = loaded.stderr.decode(errors="replace")[-300:]
            raise AssertionError("relay daemon cannot resolve the pinned Node image")
        self.proxy.terminate()
        self.proxy.wait(timeout=10)
        routes = self.run("relay", ["ip", "route", "show", "default"]).strip() + self.run("relay", ["ip", "-6", "route", "show", "default"]).strip()
        if routes:
            raise AssertionError("relay retains a default route after image staging")
        self.evidence["relay_image_staging"] = {"transport": "loopback CONNECT proxy during setup", "proxy_stopped": True, "pinned_reference_resolves": True, "relay_default_routes": False}

    def cover(self):
        site = self.work / "site"
        site.mkdir(mode=0o755)
        (site / "index.html").write_text('<!doctype html><html lang="en"><head><title>Atlas field journal</title><link rel="stylesheet" href="journal.css"></head><body><h1>Atlas field journal</h1><p>A synthetic archive of coastal observations, local maps and weather notes from imaginary islands.</p><a href="notes.html">Field notes</a></body></html>\n')
        (site / "journal.css").write_text("body { max-width: 48rem; margin: 3rem auto; color: #243; }\n")
        (site / "notes.html").write_text("<!doctype html><title>Notes</title><p>Synthetic coastal weather observations.</p>\n")
        self.stage = "local-ACME-API-certificate-fixture"
        ca = self.work / "acme-ca"
        ca.mkdir(mode=0o700)
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca / "key.pem", "-out", ca / "cert.pem", "-days", "2", "-subj", "/CN=Disposable ACME API CA"])
        command(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", ca / "api.key", "-out", ca / "api.csr", "-subj", "/CN=localhost"])
        (ca / "api.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        command(["openssl", "x509", "-req", "-in", ca / "api.csr", "-CA", ca / "cert.pem", "-CAkey", ca / "key.pem", "-CAcreateserial", "-out", ca / "api.pem", "-days", "2", "-extfile", ca / "api.ext"])
        private_json(self.work / "pebble.json", {"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000", "certificate": str(ca / "api.pem"), "privateKey": str(ca / "api.key"), "httpPort": 80, "tlsPort": 5001, "externalAccountBindingRequired": False}})
        self.stage = "local-ACME-DNS-and-management-readiness"
        self.spawn("exit", ["dnsmasq", "--keep-in-foreground", "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=127.0.0.1", "--port=53535", "--address=/.example.test/127.0.0.1"], "dns")
        self.spawn("exit", [self.work / "bin/pebble", "-config", self.work / "pebble.json", "-dnsserver", "127.0.0.1:53535"], "pebble", env={**os.environ, "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_VA_ALWAYS_VALID": "0"})
        for _ in range(90):
            result = subprocess.run(["curl", "-fsS", "--cacert", str(ca / "cert.pem"), "--noproxy", "*", "https://localhost:15000/roots/0"], capture_output=True, check=False)
            if result.returncode == 0 and b"BEGIN CERTIFICATE" in result.stdout:
                self.trust = self.work / "root.pem"
                self.trust.write_bytes(result.stdout)
                break
            time.sleep(1)
        else:
            raise AssertionError("real local ACME root unavailable")
        self.cover_vars = {**self.topology["exit"], "cover_acme_agree_tos": True, "cover_acme_http_reachable": True, "cover_disposable_test": True, "cover_acme_directory": "https://localhost:14000/dir", "cover_acme_test_ca": str(ca / "cert.pem"), "cover_certificate_trust": str(self.trust)}
        self.stage = "actual-owned-cover-role"
        self.play(["cover_site"], variables=self.cover_vars)
        self.first_site = Path("/var/lib/cover-site/active").resolve()
        command(["/usr/local/libexec/cover-site/lifecycle.py", "health"])
        command(["openssl", "x509", "-in", self.first_site / "certificate/cert.pem", "-checkend", "3600", "-noout"])
        self.stage = "role-generated-relay-origin-replica"
        conf = self.work / "relay-nginx.conf"
        conf.write_text('pid ' + str(self.work / 'relay-nginx.pid') + ';\nerror_log ' + str(self.work / 'relay-nginx.private.log') + ';\nevents {}\nhttp { include /etc/nginx/mime.types; include ' + str(self.first_site / 'site.conf') + '; }\n')
        self.relay_nginx_conf = conf
        self.spawn("relay", ["nginx", "-c", conf, "-g", "daemon off;"], "relay-origin")
        self.evidence["scenarios"]["origin"] = {"issued_by": "real-local-Pebble-HTTP01", "chain_SAN_expiry": "cover-role-health-and-openssl-checkend", "replica": "same-role-generated-site.conf-in-relay-host-network"}

    def base(self, kind, extra_public=None):
        host = self.topology[kind]
        variables = {**host, "base_ssh_trusted_cidrs": ["192.0.2.30/32", "2001:db8:47::30/128"], "base_firewall_enabled": True, "base_firewall_allow_icmp_echo": True, "base_firewall_allow_dhcpv6_client": False}
        if extra_public:
            variables["base_firewall_vpn_ports"] = variables["base_firewall_vpn_ports"] + [{"proto": "tcp", "port": extra_public}]
        self.play([{"name": str(ROOT / "ansible/roles/base"), "tasks_from": "firewall.yml"}], kind=kind, variables=variables)

    def deploy_node(self, kind):
        self.stage = kind + "-node-deployment"
        pki = self.work / (kind + "-pki")
        secret, credentials = PKI.fixture(pki)
        directory = "/opt/" + self.prefix + "-" + kind
        self.node_inputs[kind] = {"secret": secret, "credentials": credentials, "port": 2222, "config": {}}
        host = self.topology[kind]
        variables = {**host, "cp_placement": "exit", "remnawave_node_dir": directory, "remnawave_node_secret_key_file": str(pki / "secret"), "remnawave_node_management_credentials_file": str(pki / "credentials.json"), "remnawave_node_management_address": "127.0.0.1", "remnawave_node_management_source": "127.0.0.1", "remnawave_node_management_delegate": kind, "remnawave_node_timeout": 120}
        try:
            self.play(["remnawave_node"], kind=kind, variables=variables)
        except AssertionError:
            try:
                self.node_diagnostics(kind)
            except Exception:
                self.evidence["public_node_diagnostics"] = "collection failed"
            raise
        env = self.relay_env if kind == "relay" else None
        command(["docker", "cp", self.assets / "geoip.dat", "vpn-remnanode:/usr/local/share/xray/geoip.dat"], env=env)
        inspect = json.loads(command(["docker", "inspect", "vpn-remnanode"], env=env))[0]
        expected = Path("/var/run/netns/" + self.ns(kind)) if self.ns(kind) else Path("/proc/1/ns/net")
        if os.stat(expected).st_ino != os.stat("/proc/" + str(inspect["State"]["Pid"]) + "/ns/net").st_ino:
            raise AssertionError("Node does not share the actual origin network namespace")
        self.evidence["scenarios"][kind + "_node"] = {"network_mode": inspect["HostConfig"]["NetworkMode"], "actual_namespace_matches_origin": True}
        return variables

    def node_diagnostics(self, kind):
        env = self.relay_env if kind == "relay" else None
        facts = {}

        def result(args, **kwargs):
            return subprocess.run([str(x) for x in args], capture_output=True, env=kwargs.get("env"), timeout=30, check=False)

        state = subprocess.run(["cat", "/opt/" + self.prefix + "-" + kind + "/state.json"], capture_output=True, timeout=10, check=False)
        if state.returncode == 0:
            try:
                value = json.loads(state.stdout)
                facts["state"] = {key: value.get(key) is not None for key in ("checked", "previous", "pending")}
                facts["restoration_stopped"] = bool((value.get("restoration") or {}).get("stopped"))
            except json.JSONDecodeError:
                facts["state"] = "unparseable"
        inspect = result(["docker", "inspect", "vpn-remnanode"], env=env)
        if inspect.returncode == 0:
            data = json.loads(inspect.stdout)[0]
            state = data.get("State", {})
            facts["container"] = {key: state.get(key) for key in ("Status", "Running", "ExitCode", "Error", "OOMKilled")}
            facts["health_output"] = [str(entry.get("Output", ""))[-300:] for entry in state.get("Health", {}).get("Log", [])[-2:]]
            facts["mounts"] = [str(mount.get("Source")) + ":" + str(mount.get("RW")) for mount in data.get("Mounts", [])]
        else:
            facts["container"] = "absent"
            facts["inspect_error"] = inspect.stderr.decode(errors="replace")[-300:]
        if kind == "relay":
            log = (self.work / "relay-docker.private.log")
            if log.exists():
                lines = log.read_text(errors="replace").splitlines()
                facts["daemon_errors"] = [line[-400:] for line in lines if "level=error" in line][-6:]
                facts["daemon_warnings"] = [line[-300:] for line in lines if "level=warning" in line][-4:]
        listeners = result((["ip", "netns", "exec", self.ns(kind)] if self.ns(kind) else []) + ["ss", "-H", "-ltn"])
        facts["listeners"] = [line.split()[3] for line in listeners.stdout.decode(errors="replace").splitlines() if len(line.split()) > 3]
        acl = result((["ip", "netns", "exec", self.ns(kind)] if self.ns(kind) else []) + ["nft", "-j", "list", "table", "inet", "vpn_base"])
        if acl.returncode == 0:
            rules = json.loads(acl.stdout).get("nftables", [])
            facts["active_acl"] = {"present": True, "elements": len(rules)}
        else:
            facts["active_acl"] = {"present": False}
        releases = Path("/opt/" + self.prefix + "-" + kind + "/releases")
        facts["release_count"] = len(list(releases.iterdir())) if releases.is_dir() else 0
        self.evidence["public_node_diagnostics"] = facts

    def api_start(self, kind, configuration):
        obj = {**self.node_inputs[kind], "config": configuration}
        path = self.work / (kind + "-start.private.json")
        private_json(path, obj)
        result = json.loads(self.run(kind, [ROOT / ".venv/bin/python", __file__, "node-start", path]))
        if result["xrayVersion"] != bundle.CORE_VERSION:
            raise AssertionError("API core version does not match stock binary")

    def activate_configs(self, candidate):
        if getattr(self, "installed_identity", None) == candidate.name:
            for kind in ("exit", "relay"):
                path = self.work / (kind + "-start.private.json")
                self.run(kind, [ROOT / ".venv/bin/python", __file__, "node-health", path])
            return
        for kind in ("exit", "relay"):
            config = candidate / (kind + ".json")
            self.stage = kind + "-core-config-test"
            command([self.xray, "run", "-test", "-config", config], env=self.core_env)
            original = json.loads(config.read_text())
            instrumented = copy.deepcopy(original)
            # Disposable-only observations, never added by the renderer or
            # written into immutable bundle bytes. Receipts bind both hashes.
            instrumented["log"]["access"] = "/dev/stdout"
            effective = json.dumps(instrumented, sort_keys=True).encode()
            overlays = self.evidence.setdefault("runtime_observation_overlays", {})
            overlays.setdefault(candidate.name, {})[kind] = {"bundle_file_sha256": hashlib.sha256(config.read_bytes()).hexdigest(), "effective_config_canonical_sha256": hashlib.sha256(effective).hexdigest(), "changes": {"log.access": "/dev/stdout"}, "scope": "disposable-only; routing/finalRules unchanged"}
            observed_config = self.work / (kind + "-observed-config.private.json")
            private_json(observed_config, instrumented)
            command([self.xray, "run", "-test", "-config", observed_config], env=self.core_env)
            self.stage = kind + "-core-api-start"
            self.api_start(kind, instrumented)
        for config in (candidate / "clients").glob("*.json"):
            command([self.xray, "run", "-test", "-config", config], env=self.core_env)
        self.installed_identity = candidate.name

    def client(self, candidate, name, port, *, version=4, change=None):
        self.stage = "client-" + name + "-listener"
        self.evidence["public_client_phase"] = "load"
        if name in self.client_processes:
            old = self.client_processes.pop(name)
            old.terminate()
            old.wait(timeout=10)
        config = json.loads((candidate / ("clients/" + name + ".json")).read_text())
        self.evidence["public_client_phase"] = "override"
        config["inbounds"][0]["port"] = port
        if version == 6:
            host = self.topology["exit" if name.startswith("direct") else "relay"]
            config["outbounds"][0]["settings"]["vnext"][0]["address"] = host["public_ipv6"]
        if change:
            change(config)
        path = self.work / ("client-" + name + ".private.json")
        self.evidence["public_client_phase"] = "write"
        private_json(path, config)
        self.evidence["public_client_phase"] = "spawn"
        process = self.spawn("client", [self.xray, "run", "-config", path], "client-" + name, env=self.core_env)
        self.client_processes[name] = process
        self.evidence["public_client_phase"] = "ready"

        def client_facts():
            try:
                self.evidence["public_client_log"] = (self.work / ("client-" + name + ".private.log")).read_text(errors="replace")[-500:]
                self.evidence["public_client_exit"] = process.poll()
                namespace = self.ns("client")
                listeners = subprocess.run(["ip", "netns", "exec", namespace, "ss", "-H", "-ltn"], capture_output=True, timeout=30, check=False)
                self.evidence["public_client_listeners"] = [line.split()[3] for line in listeners.stdout.decode(errors="replace").splitlines() if len(line.split()) > 3]
            except Exception:
                self.evidence["public_client_facts"] = "unavailable"

        try:
            for _ in range(300):
                if process.poll() is not None:
                    client_facts()
                    raise AssertionError("Xray client exited before its listener opened")
                if self.run("client", [ROOT / ".venv/bin/python", __file__, "tcp", "127.0.0.1", str(port)]).strip() == b"open":
                    break
                time.sleep(.1)
            else:
                client_facts()
                raise AssertionError("real local client listener unavailable")
        except AssertionError:
            if "public_client_listeners" not in self.evidence:
                client_facts()
            raise

    def transfer(self, port=1080, size=1048576, *, expected=True, address="192.0.2.100", target=18080):
        return self.run("client", [ROOT / ".venv/bin/python", HERE / "traffic.py", "transfer", port, size, address, target], expected=expected, timeout=240)

    def tls_matrix(self):
        expected = (self.work / "site/index.html").read_bytes()
        origin_results = {}
        for kind in ("exit", "relay"):
            host = self.topology[kind]
            public_port = host.get("exit_direct_port", host.get("relay_slot_ports", [None])[0])
            for tls in ("1.2", "1.3"):
                for http in ("1.1", "2"):
                    flags = ["--tlsv" + tls, "--tls-max", tls, "--http" + http]
                    visitor_body = self.work / "visitor-body.private.bin"
                    protocol = self.run("client", ["curl", "-fsS", "--max-time", "15", "--noproxy", "*", "--cacert", self.trust, "--resolve", f"cover.example.test:{public_port}:{host['public_ipv4']}", *flags, "--output", visitor_body, "--write-out", "%{http_version}", f"https://cover.example.test:{public_port}/"])
                    if visitor_body.read_bytes() != expected or protocol.strip() != http.encode():
                        raise AssertionError("actual public REALITY content or negotiated H1/H2 differs from owned origin")
            for sni in (None, "unknown.example.test", "cover.example.test"):
                for hostname in ("cover.example.test", "unknown.example.test"):
                    for path in ("/", "/absent", "/panel", "/metrics"):
                        request = {"sni": sni, "host": hostname, "path": path}
                        testfile = self.work / "visitor.private.json"
                        private_json(testfile, request)
                        origin = self.run(kind, [ROOT / ".venv/bin/python", __file__, "visitor", "127.0.0.1", str(host["cover_tls_port"]), testfile])
                        public = self.run("client", [ROOT / ".venv/bin/python", __file__, "visitor", host["public_ipv4"], str(public_port), testfile])
                        if json.loads(origin) != json.loads(public):
                            raise AssertionError("unknown/missing SNI/Host/path differs from actual origin")
                        origin_results[str(request)] = json.loads(origin)
        self.evidence["scenarios"]["visitor_matrix"] = {"TLS": ["1.2", "1.3"], "HTTP": ["1.1", "2"], "baseline_cases": len(origin_results), "baseline": origin_results}

    def denied_ports(self):
        checks = []
        for kind in ("exit", "relay"):
            for version in (4, 6):
                host = self.topology[kind]
                for port in (host["cover_tls_port"], 2222, 9100):
                    if port == 9100:
                        if self.run(kind, [ROOT / ".venv/bin/python", __file__, "tcp", host["public_ipv" + str(version)], "9100"]).strip() != b"open":
                            raise AssertionError("exporter canary absent; deny observation would be vacuous")
                    result = self.run("outsider", [ROOT / ".venv/bin/python", __file__, "tcp", host["public_ipv" + str(version)], str(port)])
                    if result.strip() != b"closed":
                        raise AssertionError("private origin/API/exporter externally reachable")
                    checks.append({"node": kind, "version": version, "port": port, "denied": True})
        for version in (4, 6):
            destination = self.topology["exit"]["public_ipv" + str(version)]
            if self.run("outsider", [ROOT / ".venv/bin/python", __file__, "tcp", destination, "18444"]).strip() != b"closed":
                raise AssertionError("transit reachable from undeclared source")
            if self.run("relay", [ROOT / ".venv/bin/python", __file__, "tcp", destination, "18444"]).strip() != b"open":
                raise AssertionError("declared relay family cannot reach transit")
            banner = self.run("client", [ROOT / ".venv/bin/python", __file__, "ssh-banner", destination])
            if not banner.startswith(b"SSH-2.0-"):
                raise AssertionError("independent trusted SSH path unavailable")
            if self.run("outsider", [ROOT / ".venv/bin/python", __file__, "tcp", destination, "22"]).strip() != b"closed":
                raise AssertionError("SSH opened to unrelated sources")
            checks.append({"node": "exit", "version": version, "port": 22, "trusted_banner": True, "unrelated_denied": True})
        self.evidence["scenarios"]["source_acl"] = checks

    def capture_routes(self, label, action, *, slot=0, expected_family=6):
        capture = self.work / (label + ".private.pcap")
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        process = self.spawn("exit", ["tcpdump", "-i", "any", "-nn", "-U", "-w", capture, "tcp port 18444 or tcp port 18082 or tcp port 18080"], "capture-" + label)
        samples = {"exit": [], "relay": []}
        stop = threading.Event()
        sampling_errors = []
        def sample():
            try:
                while not stop.is_set():
                    for kind in samples:
                        samples[kind].append(self.run(kind, ["ss", "-H", "-tn", "state", "established"]))
                    stop.wait(.05)
            except Exception as error:
                sampling_errors.append(error)
        watcher = threading.Thread(target=sample, daemon=True)
        time.sleep(.5)
        watcher.start()
        try:
            application = json.loads(action())
        finally:
            stop.set()
            watcher.join(timeout=10)
            time.sleep(.5)
            process.terminate()
            process.wait(timeout=10)
        if watcher.is_alive() or sampling_errors:
            raise AssertionError("actual established-socket observation failed")
        records = [json.loads(line) for line in (self.work / "sink-sources.private.jsonl").read_text().splitlines()]
        matching = [record for record in records if record["flow_id"] == application["flow_id"]]
        if len(matching) != 1 or any(matching[0][key] != application[key] for key in ("payload_sha256", "bytes_each_direction")):
            raise AssertionError("application transfer lacks matching sink hash/byte receipt")
        expected_source = "192.0.2.10" if slot == 0 else "192.0.2.50"
        if matching[0]["source"] != expected_source:
            raise AssertionError("application source escaped the selected exit/upstream")
        decoded = command(["tcpdump", "-nn", "-tt", "-S", "-r", capture])
        streams = captured_streams(decoded)
        family_bytes = {}
        established = {}
        size = application["bytes_each_direction"]
        for version in (4, 6):
            remote = self.topology["exit"]["public_ipv" + str(version)] + ".18444"
            source_prefix = self.topology["relay"]["relay_egress_ipv" + str(version)] + "."
            candidates = [(source, dest, count, streams.get((dest, source), 0)) for (source, dest), count in streams.items() if dest == remote and source.startswith(source_prefix)]
            family_bytes[str(version)] = {"upload": sum(item[2] for item in candidates), "download": sum(item[3] for item in candidates)}
            carrying = [item for item in candidates if item[2] >= size and item[3] >= size]
            established[str(version)] = any(established_pair(samples["relay"], source, dest) and established_pair(samples["exit"], source, dest) for source, dest, _up, _down in carrying)
        other = str(4 if expected_family == 6 else 6)
        # Probes use HTTP204/18081, never the application's hash protocol.
        # Bound alternate-family payload below 64 KiB, versus >=1 MiB/flow.
        if size < 1048576 or not established[str(expected_family)] or max(family_bytes[other].values()) >= 65536:
            raise AssertionError("route winner lacks an established accepted application-carrying socket or alternate probe traffic exceeds bound")
        observations = {}
        for kind in ("relay", "exit"):
            logs = command(["docker", "logs", "--since", since, "vpn-remnanode"], env=self.relay_env if kind == "relay" else None, combined=True)
            inbound = "slot-" + str(slot) + "-v4" if kind == "relay" else "transit-v" + str(expected_family)
            outbound = "slot-" + str(slot) + "-v" + str(expected_family) if kind == "relay" else "egress-" + str(slot)
            observed = [line for line in logs.decode().splitlines() if "tcp:192.0.2.100:18080" in line and re.search(r"\[" + re.escape(inbound) + r"\s*(?:->|>>)\s*" + re.escape(outbound) + r"\]", line)]
            if len(observed) != 1:
                raise AssertionError("application-specific real core inbound/outbound observation is missing or ambiguous")
            observations[kind] = {"inbound": inbound, "outbound": outbound, "application_flow_observations": len(observed)}
        report = {"application": application, "sink_receipt": matching[0], "winner_family": expected_family, "unique_tcp_payload_bytes": family_bytes, "established_accepted_socket": established, "core_observations": observations, "alternate_family_probe_bound_bytes": 65536, "pcap_sha256": hashlib.sha256(capture.read_bytes()).hexdigest()}
        self.evidence["scenarios"][label] = report
        return report

    def failures(self, candidate):
        self.client(candidate, "relay-0", 1080)
        time.sleep(5)
        self.capture_routes("preferred_ipv6", lambda: self.transfer(), expected_family=6)
        self.run("relay", ["nft", "add", "table", "inet", "profile_fault"])
        self.run("relay", ["nft", "add", "chain", "inet", "profile_fault", "output", "{ type filter hook output priority -10; policy accept; }"])
        self.run("relay", ["nft", "add", "rule", "inet", "profile_fault", "output", "ip6", "daddr", "2001:db8:47::10", "tcp", "dport", "18444", "reject"])
        # Existing IPv6 H2 sessions must actually die; observatory includes its
        # transport timeout. Do not call preference instant or session migration.
        time.sleep(15)
        self.capture_routes("same_exit_ipv4", lambda: self.transfer(), expected_family=4)
        self.run("relay", ["nft", "add", "rule", "inet", "profile_fault", "output", "ip", "daddr", "192.0.2.10", "tcp", "dport", "18444", "reject"])
        time.sleep(2)
        self.transfer(expected=False)
        # Explicit direct remains a different selectable profile, never an
        # automatic relay rescue. No client direct file is modified by failover.
        self.client(candidate, "direct-0", 2080)
        self.transfer(2080)
        self.run("relay", ["nft", "delete", "table", "inet", "profile_fault"])
        time.sleep(15)
        self.capture_routes("restored_preferred_ipv6", lambda: self.transfer(), expected_family=6)
        self.evidence["scenarios"]["both_down"] = {"relay_transfer": "denied", "explicit_direct_transfer": "works", "relay_freedom_fallback": False}

    def adversarial(self, candidate):
        def wrong_key(config):
            config["outbounds"][0]["streamSettings"]["realitySettings"]["password"] = self.secret["profiles_credentials"]["exit"]["public_key"]
        def wrong_short(config):
            config["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = secrets.token_hex(8)
        def wrong_uuid(config):
            config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = str(uuid.uuid4())
        for label, mutation in (("wrong-key", wrong_key), ("wrong-shortid", wrong_short), ("correct-reality-wrong-vless", wrong_uuid)):
            self.client(candidate, "relay-0", 1080, change=mutation)
            self.transfer(expected=False)
            self.evidence["scenarios"][label] = "no-tunnel"
        self.client(candidate, "relay-0", 1080)
        credential = self.secret["profiles_credentials"]["exit"]
        count_before = len((self.work / "sink-sources.private.jsonl").read_text().splitlines())
        captures = {}
        for offset, fragmented in ((0, 0), (-301, 0), (301, 0), (0, 17)):
            name = f"clock-{offset}-fragment-{fragmented}"
            file = self.work / (name + ".private.json")
            capture = self.work / (name + ".hello.private.bin")
            state = self.work / (name + ".replay-state.private.json")
            private_json(file, {"address": "192.0.2.10:18443", "sni": "cover.example.test", "public_key": credential["public_key"], "short_id": credential["short_ids"][0], "offset_seconds": offset, "capture": str(capture), "state": str(state), "trust": str(self.trust), "fragment": fragmented})
            result = json.loads(self.run("client", [self.probe_binary, file]))
            if not result["tls_handshake_complete"] or result["reality_authenticated"] != (offset == 0) or result["origin_chain_verified"] != (offset != 0):
                raise AssertionError("REALITY clock budget lacks a real authenticated TLS/origin verdict")
            captures[name] = (capture, state, result)
            self.evidence["scenarios"][name] = result
        fresh, state, original = captures["clock-0-fragment-0"]
        replay_options = {"address": "192.0.2.10:18443", "sni": "cover.example.test", "public_key": credential["public_key"], "replay_state": str(state), "trust": str(self.trust)}
        replay_file = self.work / "exact-replay.private.json"
        private_json(replay_file, replay_options)
        replay = json.loads(self.run("client", [self.probe_binary, replay_file]))
        recorded_digest = hashlib.sha256(fresh.read_bytes()).hexdigest()
        if not replay["tls_handshake_complete"] or not replay["reality_authenticated"] or replay["origin_chain_verified"]:
            raise AssertionError("positive exact-replay authentication control failed")
        if replay["record_sha256"] != recorded_digest or any(replay[key] != original[key] for key in ("hello_sha256", "record_sha256", "recorded_unix")):
            raise AssertionError("positive replay did not transmit the exact recorded ClientHello")
        self.evidence["scenarios"]["fresh_replay"] = replay
        if len((self.work / "sink-sources.private.jsonl").read_text().splitlines()) != count_before:
            raise AssertionError("timestamp/replay probe reached an application sink")
        self.transfer(1080)  # legitimate path unaffected by probes
        count_before = len((self.work / "sink-sources.private.jsonl").read_text().splitlines())
        for length in (1, 3, 16, 80):
            self.run("client", [ROOT / ".venv/bin/python", __file__, "malformed", "192.0.2.10", "18443", fresh, str(length)])
        # Exercise expiry of precisely the same recorded authenticated hello,
        # not an unrelated wrong-key handshake. The stated five-minute budget
        # is tested against wall time on the real stock server.
        time.sleep(302)
        expired = json.loads(self.run("client", [self.probe_binary, replay_file]))
        if not expired["tls_handshake_complete"] or expired["reality_authenticated"] or not expired["origin_chain_verified"]:
            raise AssertionError("expired exact Hello did not fail REALITY authentication into a verified actual origin")
        if any(expired[key] != original[key] for key in ("hello_sha256", "record_sha256", "recorded_unix")):
            raise AssertionError("expired replay changed recorded Hello or ephemeral replay authority")
        if time.time() - expired["recorded_unix"] < 302:
            raise AssertionError("exact replay expiry wait was not real wall time")
        self.evidence["scenarios"]["expired_replay"] = expired
        if len((self.work / "sink-sources.private.jsonl").read_text().splitlines()) != count_before:
            raise AssertionError("malformed/expired replay reached an application sink")
        self.evidence["scenarios"]["replay_limit"] = "Exact fresh Hello with privately retained ephemeral keys authenticates TLS; after real 302s the same Hello receives a verified origin certificate, not REALITY authentication. No VLESS/application payload is sent by the probe. maxTimeDiff is a time window, not a replay cache."
        self.transfer(1080)

    def fanout(self, candidate):
        self.base("relay", extra_public=20443)
        fanout = self.work / "fanout-nginx.conf"
        fanout.write_text('load_module /usr/lib/nginx/modules/ngx_stream_module.so;\npid ' + str(self.work / 'fanout-nginx.pid') + ';\nevents {}\nstream { map $ssl_preread_server_name $slot { cover.example.test 127.0.0.1:19443; default 127.0.0.1:19445; } server { listen 20443; ssl_preread on; proxy_pass $slot; } }\n')
        process = self.spawn("relay", ["nginx", "-c", fanout, "-g", "daemon off;"], "fanout")
        time.sleep(1)
        def fanout_port(config):
            config["outbounds"][0]["settings"]["vnext"][0]["port"] = 20443
        self.client(candidate, "relay-0", 1080, change=fanout_port)
        self.transfer(1080)
        self.client(candidate, "relay-20", 1100, change=fanout_port)
        self.transfer(1100, expected=False)
        # The same user's explicit port must work through actual third-party
        # SOCKS upstream, demonstrating failure was fanout, not credentials.
        self.client(candidate, "relay-20", 1100)
        self.capture_routes("configured_slot_upstream", lambda: self.transfer(1100), slot=1, expected_family=6)
        sources = [json.loads(line)["source"] for line in (self.work / "sink-sources.private.jsonl").read_text().splitlines()]
        if "192.0.2.50" not in sources:
            raise AssertionError("configured slot did not traverse disposable upstream")
        self.client(candidate, "relay-21", 1101)
        self.transfer(1101, expected=False)
        process.terminate()
        process.wait(timeout=10)
        self.base("relay")
        self.client(candidate, "relay-0", 1080)
        self.evidence["scenarios"]["sni_feasibility"] = {"real_ssl_preread_passthrough": True, "same_SNI_slot0": "works", "same_SNI_slot1": "wrong-fixed-slot-no-tunnel", "explicit_ports_slot1": "works-via-upstream", "mode_switch": "operator-explicit-only"}
        self.evidence["scenarios"]["empty_slot"] = "blackhole-no-freedom"

    def load(self, candidate):
        for i in range(20):
            self.client(candidate, "relay-" + str(i), 1080 + i)
        report = json.loads(self.run("client", [ROOT / ".venv/bin/python", HERE / "traffic.py", "load", *range(1080, 1100)], timeout=360))
        if report["bytes_each_direction"] != 20 * 1048576 or report["flows"] != 80:
            raise AssertionError("load acceptance volume incomplete")
        self.evidence["scenarios"]["load"] = report
        self.evidence["scenarios"]["large_transfer"] = json.loads(self.transfer(1080, 20 * 1048576))
        time.sleep(10)
        self.transfer(1080)
        self.client(candidate, "relay-0", 1080)
        self.transfer(1080)
        sources = [json.loads(line)["source"] for line in (self.work / "sink-sources.private.jsonl").read_text().splitlines()]
        if any(source not in ("192.0.2.10", "192.0.2.50") for source in sources):
            raise AssertionError("relay/client egress leaked directly to sink")
        self.evidence["scenarios"]["idle_reconnect_no_leak"] = {"idle_seconds": 10, "sink_sources": sorted(set(sources)), "sha256_integrity": "all-bidirectional-flows"}
        self.transfer(1080, expected=False, address="192.168.47.1", target=18080)

    def usable(self, candidate):
        identity = candidate.name
        receipts = self.output / "receipts"
        receipts.mkdir(mode=0o700, exist_ok=True)
        private_json(receipts / (identity + ".json"), {"bundle_id": identity, "state": "usable-in-disposable-runtime", "evidence": self.evidence})
        link = self.output / ".current-new"
        if link.is_symlink():
            link.unlink()
        link.symlink_to("versions/" + identity)
        os.replace(link, self.output / "current")

    def idempotence_rollback(self, candidate):
        self.usable(candidate)
        before = {str(path.relative_to(candidate)): hashlib.sha256(path.read_bytes()).hexdigest() for path in candidate.rglob("*") if path.is_file()}
        repeated, output = self.render()
        if repeated != candidate or b"changed=0" not in output:
            raise AssertionError("profile playbook not idempotent")
        if before != {str(path.relative_to(candidate)): hashlib.sha256(path.read_bytes()).hexdigest() for path in candidate.rglob("*") if path.is_file()}:
            raise AssertionError("idempotence changed usable bytes")
        core_pids = {kind: self.run(kind, ["docker", "exec", "vpn-remnanode", "/command/s6-svstat", "-o", "pid", "/run/service/xray"], env=self.relay_env if kind == "relay" else None) for kind in ("exit", "relay")}
        self.activate_configs(repeated)
        after_pids = {kind: self.run(kind, ["docker", "exec", "vpn-remnanode", "/command/s6-svstat", "-o", "pid", "/run/service/xray"], env=self.relay_env if kind == "relay" else None) for kind in ("exit", "relay")}
        if core_pids != after_pids:
            raise AssertionError("identical bundle reapplication restarted the embedded core")
        for key, value in (("cover_tls_port", True), ("reality_sni", ""), ("reality_target", "foreign.example.test:443"), ("remnawave_node_network_mode", "bridge")):
            bad = copy.deepcopy(self.topology)
            bad["exit"][key] = value
            self.render(bad, expected=False)
            if (self.output / "current").resolve() != candidate or (self.output / "candidate").resolve() != candidate:
                raise AssertionError("invalid candidate replaced checked output")
        bad_config = json.loads((candidate / "exit.json").read_text())
        bad_config["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = "invalid"
        path = self.work / "invalid-core.private.json"
        private_json(path, bad_config)
        command([self.xray, "run", "-test", "-config", path], env=self.core_env, expected=False)
        # Invalid runtime syntax never enters Node API or alters usable pointers.
        self.transfer(1080)
        revoked = self.secret["relay_client_ids"][1]
        revoked_file = self.work / "revocations.private.json"
        private_json(revoked_file, [revoked])
        old_inputs = json.loads((candidate / "inputs.private.json").read_text())
        self.secret["profiles_revoked_client_ids"] = [revoked]
        (self.work / "site/index.html").write_text((self.work / "site/index.html").read_text().replace("Atlas field journal", "Atlas coastal journal"))
        self.play(["cover_site"], variables=self.cover_vars)
        new, _ = self.render()
        self.activate_configs(new)
        self.client(new, "relay-0", 1080)
        self.transfer(1080)
        # Restore old bundle INPUTS, overlay CURRENT independent revocations,
        # render a new identity, and restore actual checked site/profile/ACL.
        old_inputs["secrets"]["profiles_revoked_client_ids"] = json.loads(revoked_file.read_text())
        restored, _ = self.render(old_inputs["topology"], old_inputs["secrets"])
        command(["/usr/local/libexec/cover-site/lifecycle.py", "rollback"])
        self.base("relay")
        self.base("exit")
        self.activate_configs(restored)
        self.client(restored, "relay-0", 1080)
        self.transfer(1080)
        self.client(candidate, "relay-1", 1081)
        self.transfer(1081, expected=False)
        if (restored / "clients/relay-1.json").exists() or revoked in (restored / "relay.json").read_text():
            raise AssertionError("rollback undid independent credential revocation")
        self.denied_ports()
        body = self.run("client", ["curl", "-fsS", "--noproxy", "*", "--cacert", self.trust, "--resolve", "cover.example.test:18443:192.0.2.10", "https://cover.example.test:18443/"])
        if b"Atlas field journal" not in body:
            raise AssertionError("rollback did not restore demonstrated original site")
        self.usable(restored)
        self.evidence["scenarios"]["idempotence_rollback"] = {"byte_identical_reapply": True, "site_profile_ACL_path_restored": True, "independent_revocation_preserved": True, "restored_bundle_id": restored.name}

    def cleanup(self):
        # Root-owned credentials/captures stay private and are erased; public
        # report carries only synthetic endpoints and measured aggregate data.
        for env in (self.relay_env, None):
            if env is not None or hasattr(self, "extract"):
                subprocess.run(["docker", "rm", "-f", "vpn-remnanode"], env=env, capture_output=True, check=False)
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        if hasattr(self, "extract"):
            subprocess.run(["docker", "rm", "-f", self.extract], capture_output=True, check=False)
        for ns in self.namespaces.values():
            subprocess.run(["ip", "netns", "del", ns], capture_output=True, check=False)
        subprocess.run(["ip", "link", "del", self.prefix + "br"], capture_output=True, check=False)
        Path("/etc/hosts").write_bytes(self.old_hosts)
        for kind in ("exit", "relay"):
            shutil.rmtree("/opt/" + self.prefix + "-" + kind, ignore_errors=True)
        subprocess.run(["systemctl", "stop", "cover-site-renew.timer", "nginx", "vpn-base-firewall.service"], capture_output=True, check=False)
        subprocess.run(["nft", "delete", "table", "inet", "vpn_base"], capture_output=True, check=False)
        for path in ("/etc/nginx/sites-enabled/cover-site.conf",):
            p = Path(path)
            if p.is_symlink() or p.exists():
                p.unlink()
        for path in ("/etc/cover-site", "/var/lib/cover-site", "/var/log/cover-site", "/var/www/cover-site-acme"):
            shutil.rmtree(path, ignore_errors=True)

    def execute(self):
        self.stage = "accepted-runtime-role-contracts"
        runtime_contracts()
        self.stage = "network"
        self.network()
        self.stage = "verified-runtime-prerequisites"
        self.prerequisites()
        self.stage = "isolated-relay-docker-daemon"
        self.relay_daemon()
        self.stage = "owned-cover-local-ACME"
        self.cover()
        # Real firewall policy is active before either API daemon starts.
        self.stage = "source-ACL-before-Node"
        self.base("relay")
        self.base("exit")
        self.deploy_node("exit")
        self.deploy_node("relay")
        for kind in ("exit", "relay"):
            for version in (4, 6):
                self.spawn(kind, [ROOT / ".venv/bin/python", __file__, "tcp-listen", self.topology[kind]["public_ipv" + str(version)], "9100"], kind + "-exporter-canary-" + str(version))
        self.spawn("sink", [ROOT / ".venv/bin/python", HERE / "traffic.py", "serve", self.work / "sink-sources.private.jsonl"], "sink")
        upstream = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "192.0.2.50", "port": 18082, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}], "outbounds": [{"protocol": "freedom"}]}
        path = self.work / "upstream.private.json"
        private_json(path, upstream)
        self.spawn("upstream", [self.xray, "run", "-config", path], "upstream", env=self.core_env)
        self.stage = "coherent-playbook-and-authorized-baseline"
        candidate, _ = self.render()
        self.stage = "core-config-activation"
        self.activate_configs(candidate)
        self.stage = "direct-profile-application-transfer"
        self.client(candidate, "direct-0", 2080)
        self.transfer(2080)
        self.stage = "relay-profile-application-transfer"
        self.client(candidate, "relay-0", 1080)
        time.sleep(5)
        self.transfer()
        self.stage = "TLS-H1-H2-origin-baselines"
        self.tls_matrix()
        self.denied_ports()
        self.stage = "same-exit-failover-and-recovery"
        self.failures(candidate)
        self.stage = "adversarial-clock-and-replay"
        self.adversarial(candidate)
        self.stage = "ssl-preread-fanout-and-fixed-slots"
        self.fanout(candidate)
        self.stage = "real-concurrent-bidirectional-load"
        self.load(candidate)
        self.stage = "idempotence-and-revocation-safe-rollback"
        self.idempotence_rollback(candidate)
        self.evidence["result"] = "PASS"
        return self.evidence


def child():
    mode = sys.argv[1]
    if mode in ("node-start", "node-health"):
        runtime_contracts()
    if mode == "node-start":
        obj = json.loads(Path(sys.argv[2]).read_text())
        LIFE.start(obj)
        print(json.dumps(LIFE.health(obj, True)))
    elif mode == "node-health":
        obj = json.loads(Path(sys.argv[2]).read_text())
        print(json.dumps(LIFE.health(obj, True)))
    elif mode == "tcp-listen":
        address = sys.argv[2]
        with socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET) as server:
            if ":" in address:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((sys.argv[2], int(sys.argv[3])))
            server.listen(16)
            while True:
                conn, _peer = server.accept()
                with conn:
                    conn.sendall(b"private-exporter-canary\n")
    elif mode == "connect-proxy":
        connect_proxy(sys.argv[2], int(sys.argv[3]))
    elif mode == "ssh-banner":
        with socket.create_connection((sys.argv[2], 22), timeout=5) as sock:
            sock.settimeout(5)
            sys.stdout.buffer.write(sock.recv(128))
    elif mode == "tcp":
        address, port = sys.argv[2], int(sys.argv[3])
        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((address, port))
            print("open" if result == 0 else "closed")
        finally:
            sock.close()
    elif mode == "visitor":
        address, port = sys.argv[2], int(sys.argv[3])
        options = json.loads(Path(sys.argv[4]).read_text())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.monotonic()
        try:
            with socket.create_connection((address, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=options["sni"]) as conn:
                    conn.settimeout(5)
                    conn.sendall(("GET " + options["path"] + " HTTP/1.1\r\nHost: " + options["host"] + "\r\nConnection: close\r\n\r\n").encode())
                    response = bytearray()
                    while True:
                        part = conn.recv(65536)
                        if not part:
                            break
                        response.extend(part)
                    parts = bytes(response).split(b"\r\n\r\n", 1)
                    status = parts[0].split(b"\r\n", 1)[0].decode()
                    body = parts[1] if len(parts) > 1 else b""
                    print(json.dumps({"status": status, "body_sha256": hashlib.sha256(body).hexdigest(), "TLS": conn.version()}))
        except (OSError, ssl.SSLError):
            print(json.dumps({"TLS": "handshake-or-stream-rejected"}))
    elif mode == "malformed":
        address, port = sys.argv[2], int(sys.argv[3])
        data = Path(sys.argv[4]).read_bytes()[:int(sys.argv[5])]
        start = time.monotonic()
        response = b""
        with socket.create_connection((address, port), timeout=5) as sock:
            sock.settimeout(3)
            try:
                sock.sendall(data)
                sock.shutdown(socket.SHUT_WR)
                response = sock.recv(65536)
            except (OSError, TimeoutError):
                pass
        print(json.dumps({"response_bytes": len(response), "seconds": time.monotonic() - start, "operation": "truncated-hello-only"}))
    else:
        raise SystemExit("unknown disposable child operation")


def main():
    guard()
    with tempfile.TemporaryDirectory(prefix="vpn-profiles-", dir="/var/tmp") as temporary:
        lab = Lab(Path(temporary))
        try:
            lab.execute()
        except Exception as error:
            lab.evidence["result"] = "FAIL"
            lab.evidence["failed_stage"] = getattr(lab, "stage", "initialization")
            lab.evidence["public_error_type"] = type(error).__name__
            if isinstance(error, PrerequisiteError):
                lab.evidence["required_prerequisite"] = str(error)
            raise
        finally:
            try:
                report_dir = ROOT / "artifacts/active-probing"
                report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                private_json(report_dir / "profiles-runtime.json", lab.evidence)
                print(json.dumps(lab.evidence, sort_keys=True, indent=2))
            finally:
                lab.cleanup()


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            child()
        else:
            main()
    except Exception:
        print("Profile disposable acceptance failed; private diagnostics withheld", file=sys.stderr)
        raise SystemExit(1) from None

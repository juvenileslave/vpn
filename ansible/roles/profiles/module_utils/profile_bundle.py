"""Coherent offline self-steal bundle renderer; all validation precedes writes."""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid
from urllib.parse import urlsplit

CORE_VERSION = "26.11.9"
NODE_IMAGE = "ghcr.io/remnawave/node:3.4.5@sha256:8f5a41708dfa86acc2561a520c9b40e2ff30812a16c28cf6bba6c365ca0f7d65"
FAMILIES = {"v4_prefer": "UseIPv4v6", "v6_prefer": "UseIPv6v4", "v4_only": "ForceIPv4"}
DNS = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class Invalid(ValueError):
    """Messages name constraints, never supplied values or credentials."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def port(value, name):
    require(type(value) is int and 1 <= value <= 65535, name + " must be an integer port 1..65535")
    return value


def cidrs(value, name):
    require(isinstance(value, list) and bool(value), name + " must be a nonempty CIDR list")
    result = []
    for item in value:
        try:
            net = ipaddress.ip_network(item, strict=True) if isinstance(item, str) and "/" in item else None
        except ValueError:
            net = None
        require(net is not None, name + " contains an invalid CIDR")
        require(net.prefixlen >= (8 if net.version == 4 else 32), name + " contains a wide CIDR")
        require(not net.is_multicast and not net.is_unspecified, name + " contains an unsafe CIDR")
        require(not net.is_loopback or str(net) in ("127.0.0.1/32", "::1/128"), name + " permits only exact standard loopback management")
        require(net.version != 6 or net.network_address.ipv4_mapped is None, name + " rejects IPv4-mapped networks")
        result.append(str(net))
    require(len(set(result)) == len(result), name + " contains duplicate CIDRs")
    return result


def public_key(private):
    """RFC 7748 Montgomery ladder; no external crypto dependency for offline render."""
    require(isinstance(private, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", private), "invalid REALITY private key")
    raw = base64.urlsafe_b64decode(private + "=")
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == private, "noncanonical REALITY private key")
    k = bytearray(raw)
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    scalar = int.from_bytes(k, "little")
    p = 2**255 - 19
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in range(254, -1, -1):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3, z3 = (da + cb)**2 % p, x1 * (da - cb)**2 % p
        x2, z2 = aa * bb % p, e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    raw_public = (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")
    return base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode()


def ids(value, name):
    require(isinstance(value, list) and bool(value), name + " must contain UUIDs")
    for item in value:
        try:
            parsed = str(uuid.UUID(item)) if isinstance(item, str) else None
        except ValueError:
            parsed = None
        require(parsed == item and parsed != str(uuid.UUID(int=0)), name + " contains an invalid UUID")
    require(len(set(value)) == len(value), name + " contains duplicate UUIDs")
    return value


def validate_upstream(outbound):
    """Syntax/credential gates before writes; actual upstream auth is runtime-only."""
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "port":
                    port(item, "upstream port")
                if key in ("password", "pass", "privateKey", "publicKey", "secretKey"):
                    require(isinstance(item, str) and bool(item), "upstream credential must be a nonempty string")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(outbound)
    protocol, settings = outbound["protocol"], outbound["settings"]
    records = settings.get("vnext" if protocol in ("vless", "vmess") else "servers")
    if protocol in ("vless", "vmess", "socks", "http", "trojan", "shadowsocks"):
        require(isinstance(records, list) and bool(records), "upstream requires explicit endpoints")
        for record in records:
            require(isinstance(record, dict) and isinstance(record.get("address"), str) and bool(record["address"]), "upstream endpoint address missing")
            port(record.get("port"), "upstream endpoint port")
            if protocol in ("vless", "vmess"):
                users = record.get("users")
                require(isinstance(users, list) and bool(users) and all(isinstance(user, dict) for user in users), "upstream users required")
                ids([user.get("id") for user in users], "upstream client UUIDs")
            if protocol in ("trojan", "shadowsocks"):
                require(isinstance(record.get("password"), str) and bool(record["password"]), "upstream password required")


def validate_host(host, kind):
    require(isinstance(host, dict), kind + " host must be a mapping")
    require(DNS.fullmatch(host.get("reality_sni", "")) is not None, "reality_sni must be one exact lowercase DNS name")
    cover = port(host.get("cover_tls_port"), "cover_tls_port")
    require(cover != 80, "cover_tls_port cannot collide with HTTP-01 TCP80")
    target = "127.0.0.1:" + str(cover)
    require(host.get("reality_target", target) == target, "reality_target conflicts with self-steal loopback origin")
    require(isinstance(host.get("cover_site_source"), str) and host["cover_site_source"].startswith("/"), "cover_site_source must be an absolute directory")
    require(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", host.get("cover_acme_email", "")) is not None, "cover_acme_email is required")
    require(host.get("remnawave_node_network_mode") == "host", "cover and node must share host network namespace")
    require(type(host.get("reality_max_time_diff_ms")) is int and host["reality_max_time_diff_ms"] > 0, "reality_max_time_diff_ms must be positive")
    ssh = port(host.get("base_ssh_port", 22), "base_ssh_port")
    api = port(host.get("node_api_port", 2222), "node_api_port")
    service = [port(host.get("exit_direct_port"), "exit_direct_port"), port(host.get("transit_port"), "transit_port")] if kind == "exit" else host.get("relay_slot_ports")
    require(isinstance(service, list) and bool(service), "relay_slot_ports must be a nonempty list")
    service = [port(x, "listener port") for x in service]
    require(len(set([cover, ssh, api, 80] + service)) == len([cover, ssh, api, 80] + service), "listener/SSH/API/origin/HTTP01 ports collide")
    public = host.get("base_firewall_vpn_ports", [])
    require(isinstance(public, list), "base_firewall_vpn_ports must be a list")
    public_pairs = set()
    for item in public:
        require(isinstance(item, dict) and set(item) == {"proto", "port"} and item.get("proto") in ("tcp", "udp"), "invalid public port declaration")
        pair = (item["proto"], port(item.get("port"), "public port"))
        require(pair not in public_pairs and pair != ("tcp", ssh), "duplicate public port or SSH conflict")
        public_pairs.add(pair)
    require(("tcp", api) not in public_pairs and ("tcp", cover) not in public_pairs, "private API/origin cannot be public")
    restricted = host.get("base_firewall_source_ports")
    require(isinstance(restricted, list), "base_firewall_source_ports must be a list")
    rules = {}
    for item in restricted:
        require(isinstance(item, dict) and set(item) == {"proto", "port", "source_cidrs"}, "invalid source port declaration")
        require(item["proto"] in ("tcp", "udp"), "source port protocol invalid")
        pair = (item["proto"], port(item["port"], "restricted port"))
        require(pair not in rules and pair not in public_pairs and pair != ("tcp", ssh), "restricted/public/SSH declarations conflict")
        require(pair != ("tcp", cover), "private cover origin cannot have a source exposure rule")
        rules[pair] = set(cidrs(item["source_cidrs"], "source_cidrs"))
    require(rules.get(("tcp", api)) == set(cidrs(host.get("node_port_allow"), "node_port_allow")), "node API ACL must equal node_port_allow")
    required_public = service[:1] if kind == "exit" else service
    require(all(("tcp", x) in public_pairs for x in required_public), "public profile listeners must be declared explicitly")
    return rules


def validate(topology, secret):
    require(isinstance(topology, dict) and isinstance(secret, dict), "bundle inputs must be mappings")
    exit_host, relay = topology.get("exit"), topology.get("relay")
    exit_rules = validate_host(exit_host, "exit")
    validate_host(relay, "relay")
    require(topology.get("slot_fanout") == "ports", "slot_fanout sni cannot distinguish slots with the single REALITY SNI; choose ports explicitly after feasibility test")
    n = topology.get("egress_slots")
    require(type(n) is int and 1 <= n <= 6, "egress_slots must be integer 1..6")
    require(len(relay["relay_slot_ports"]) == n, "relay_slot_ports must contain one port per fixed slot")
    require(topology.get("egress_family") in FAMILIES, "invalid egress_family")
    require(topology.get("s2s_family") == "v6_prefer", "self-steal relay requires s2s_family v6_prefer")
    require(topology.get("xhttp_mode") == "stream-one", "xhttp_mode must be stream-one")
    require(isinstance(topology.get("xhttp_path"), str) and re.fullmatch(r"/[^\s?#]*", topology["xhttp_path"]), "invalid xhttp_path")
    probe = urlsplit(topology.get("profiles_probe_url", ""))
    require(probe.scheme in ("http", "https") and probe.hostname and not probe.username and not probe.password, "profiles_probe_url must be an explicit credential-free HTTP(S) URL")
    sources = set()
    for version in (4, 6):
        for host, key in ((exit_host, "public_ipv" + str(version)), (relay, "public_ipv" + str(version)), (relay, "relay_egress_ipv" + str(version))):
            try:
                require(isinstance(host.get(key), str), key + " must be an address string")
                ip = ipaddress.ip_address(host.get(key, ""))
            except ValueError:
                ip = None
            require(ip is not None and ip.version == version and not ip.is_unspecified and not ip.is_multicast and not ip.is_loopback and not ip.is_link_local, key + " must be an explicit usable address")
            if key.startswith("relay_egress_"):
                sources.add(str(ip) + ("/32" if version == 4 else "/128"))
        require(ipaddress.ip_address(exit_host["public_ipv" + str(version)]) != ipaddress.ip_address(relay["public_ipv" + str(version)]), "exit and relay public addresses must differ")
    require(exit_rules.get(("tcp", exit_host["transit_port"])) == sources, "transit ACL must equal declared relay egress /32 and /128")
    creds = secret.get("profiles_credentials")
    require(isinstance(creds, dict) and set(creds) == {"exit", "relay"}, "profiles_credentials requires exit and relay identities")
    for kind in ("exit", "relay"):
        c = creds[kind]
        require(isinstance(c, dict) and set(c) == {"private_key", "public_key", "short_ids"}, "invalid REALITY identity fields")
        require(public_key(c["private_key"]) == c["public_key"], "REALITY key pair mismatch")
        short = c["short_ids"]
        require(isinstance(short, list) and bool(short) and all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{16}", x) for x in short) and len(short) == len(set(short)), "shortIds must be unique random 8-byte lowercase hex values")
    require(creds["exit"]["public_key"] != creds["relay"]["public_key"], "exit and relay REALITY identities must differ")
    require(not set(creds["exit"]["short_ids"]) & set(creds["relay"]["short_ids"]), "bundle shortIds must be unique across nodes")
    direct = ids(secret.get("exit_direct_client_ids"), "exit_direct_client_ids")
    transit = ids(secret.get("transit_client_ids"), "transit_client_ids")
    users = ids(secret.get("relay_client_ids"), "relay_client_ids")
    require(len(transit) == n, "transit_client_ids must contain one UUID per fixed slot")
    require(not set(direct) & set(transit) and not set(users) & set(transit), "direct/client and transit UUIDs must differ")
    slots = secret.get("profiles_user_slots")
    require(isinstance(slots, list) and len(slots) == len(users) and all(type(x) is int and 0 <= x < n for x in slots), "profiles_user_slots must map every user to a fixed slot")
    revoked = secret.get("profiles_revoked_client_ids", [])
    require(isinstance(revoked, list), "profiles_revoked_client_ids must be a list")
    if revoked:
        ids(revoked, "profiles_revoked_client_ids")
    upstreams = secret.get("profiles_upstreams", {})
    require(isinstance(upstreams, dict), "profiles_upstreams must be a mapping")
    for slot, outbound in upstreams.items():
        require(str(slot) in [str(x) for x in range(1, n)], "upstream slot outside fixed third-party range")
        require(isinstance(outbound, dict) and outbound.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria") and isinstance(outbound.get("settings"), dict) and bool(outbound["settings"]), "configured slots require a real explicit proxy outbound")
        require("proxySettings" not in outbound and "dialerProxy" not in outbound.get("streamSettings", {}).get("sockopt", {}), "upstream cannot escape through an undeclared chained outbound")
        validate_upstream(outbound)
    return creds, set(revoked)


def stream(host, credential, path, server=True):
    reality = {"show": False}
    if server:
        reality.update(dest="127.0.0.1:" + str(host["cover_tls_port"]), xver=0, serverNames=[host["reality_sni"]], privateKey=credential["private_key"], shortIds=credential["short_ids"], maxTimeDiff=host["reality_max_time_diff_ms"])
    else:
        reality.update(serverName=host["reality_sni"], fingerprint="firefox", password=credential["public_key"], shortId=credential["short_ids"][0])
    return {"network": "xhttp", "security": "reality", "xhttpSettings": {"path": path, "mode": "stream-one", "xPaddingBytes": "100-1000"}, "realitySettings": reality}


def inbound(tag, address, listener, clients, settings):
    result = {"tag": tag, "listen": address, "port": listener, "protocol": "vless", "settings": {"clients": clients, "decryption": "none"}, "streamSettings": copy.deepcopy(settings), "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}}
    if address == "::":
        result["streamSettings"]["sockopt"] = {"v6only": True}
    return result


def outbound(tag, host, listener, client_id, credential, path, address):
    return {"tag": tag, "protocol": "vless", "settings": {"vnext": [{"address": address, "port": listener, "users": [{"id": client_id, "encryption": "none"}]}]}, "streamSettings": stream(host, credential, path, False)}


def rule(**kwargs):
    return {"type": "field", **kwargs}


def render(topology, secret):
    credentials, revoked = validate(topology, secret)
    e, r = topology["exit"], topology["relay"]
    n, path = topology["egress_slots"], topology["xhttp_path"]
    clients = [{"id": x, "email": "direct-" + str(i)} for i, x in enumerate(secret["exit_direct_client_ids"]) if x not in revoked]
    services = [{"id": x, "email": "egress-" + str(i)} for i, x in enumerate(secret["transit_client_ids"]) if x not in revoked]
    exit_stream = stream(e, credentials["exit"], path)
    exit_config = {"log": {"loglevel": "warning"}, "inbounds": [inbound("direct-v4", "0.0.0.0", e["exit_direct_port"], clients, exit_stream), inbound("direct-v6", "::", e["exit_direct_port"], clients, exit_stream), inbound("transit-v4", "0.0.0.0", e["transit_port"], services, exit_stream), inbound("transit-v6", "::", e["transit_port"], services, exit_stream)], "outbounds": [{"tag": "block", "protocol": "blackhole"}], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [rule(ip=["geoip:private"], outboundTag="block"), rule(protocol=["bittorrent"], outboundTag="block")]}}
    family = topology["egress_family"]
    blocked = ["geoip:private"] + (["::/0"] if family == "v4_only" else [])
    exit_config["outbounds"].append({"tag": "egress-0", "protocol": "freedom", "settings": {"finalRules": [{"action": "block", "ip": blocked}]}, "streamSettings": {"sockopt": {"domainStrategy": FAMILIES[family]}}})
    exit_config["routing"]["rules"].append(rule(inboundTag=["direct-v4", "direct-v6"], outboundTag="egress-0"))
    for slot in range(n):
        if slot:
            configured = secret.get("profiles_upstreams", {}).get(str(slot), secret.get("profiles_upstreams", {}).get(slot))
            if configured:
                upstream = copy.deepcopy(configured)
                upstream["tag"] = "egress-" + str(slot)
                exit_config["outbounds"].append(upstream)
        tag = "egress-" + str(slot) if slot == 0 or configured else "block"
        exit_config["routing"]["rules"].append(rule(user=["egress-" + str(slot)], outboundTag=tag))
    exit_config["routing"]["rules"].append(rule(network="tcp,udp", outboundTag="block"))
    relay = {"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [{"tag": "block", "protocol": "blackhole"}], "routing": {"domainStrategy": "AsIs", "rules": [], "balancers": []}, "observatory": {"subjectSelector": ["slot-0-v6"], "probeURL": topology["profiles_probe_url"], "probeInterval": "2s", "enableConcurrency": True}}
    for slot in range(n):
        users = [{"id": x, "email": "user-" + str(i)} for i, x in enumerate(secret["relay_client_ids"]) if secret["profiles_user_slots"][i] == slot and x not in revoked]
        for address, suffix in (("0.0.0.0", "v4"), ("::", "v6")):
            relay["inbounds"].append(inbound("slot-" + str(slot) + "-" + suffix, address, r["relay_slot_ports"][slot], users, stream(r, credentials["relay"], path)))
        for version in (6, 4):
            relay["outbounds"].append(outbound("slot-" + str(slot) + "-v" + str(version), e, e["transit_port"], secret["transit_client_ids"][slot], credentials["exit"], path, e["public_ipv" + str(version)]))
        # Each slot probes through its own real service credentials. Empty slots
        # report unhealthy and their IPv4 dial remains blackholed at the exit.
        if slot:
            relay["observatory"]["subjectSelector"].append("slot-" + str(slot) + "-v6")
        relay["routing"]["balancers"].append({"tag": "slot-" + str(slot), "selector": ["slot-" + str(slot) + "-v6"], "fallbackTag": "slot-" + str(slot) + "-v4", "strategy": {"type": "leastPing"}})
        for i, value in enumerate(secret["profiles_user_slots"]):
            if value == slot:
                relay["routing"]["rules"].append(rule(user=["user-" + str(i)], balancerTag="slot-" + str(slot)))
    relay["routing"]["rules"].append(rule(network="tcp,udp", outboundTag="block"))
    files = {"exit.json": exit_config, "relay.json": relay}
    for kind, host, user_ids, credential in (("direct", e, secret["exit_direct_client_ids"], credentials["exit"]), ("relay", r, secret["relay_client_ids"], credentials["relay"])):
        for i, client_id in enumerate(user_ids):
            if client_id in revoked:
                continue
            listener = host["exit_direct_port"] if kind == "direct" else host["relay_slot_ports"][secret["profiles_user_slots"][i]]
            files["clients/" + kind + "-" + str(i) + ".json"] = {"log": {"loglevel": "warning"}, "inbounds": [{"tag": "local", "listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"udp": False}}], "outbounds": [outbound("proxy", host, listener, client_id, credential, path, host["public_ipv4"]), {"tag": "block", "protocol": "blackhole"}], "routing": {"rules": [rule(network="tcp,udp", outboundTag="proxy")]}}
    files["firewall.json"] = {kind: {"base_firewall_vpn_ports": host["base_firewall_vpn_ports"], "base_firewall_source_ports": host["base_firewall_source_ports"]} for kind, host in (("exit", e), ("relay", r))}
    files["inputs.private.json"] = {"topology": topology, "secrets": secret}
    serialized = {name: json.dumps(value, sort_keys=True, indent=2) + "\n" for name, value in files.items()}
    identity = hashlib.sha256(json.dumps(serialized, sort_keys=True).encode()).hexdigest()
    serialized["manifest.json"] = json.dumps({"schema": 1, "bundle_id": identity, "state": "candidate-not-runtime-validated", "core_version": CORE_VERSION, "node_image": NODE_IMAGE, "slot_fanout": "ports", "hosts": {kind: {"reality_sni": host["reality_sni"], "public_ipv4": host["public_ipv4"], "public_ipv6": host["public_ipv6"], "origin": "127.0.0.1:" + str(host["cover_tls_port"])} for kind, host in (("exit", e), ("relay", r))}, "files": sorted(name for name in serialized if name != "inputs.private.json")}, sort_keys=True, indent=2) + "\n"
    return identity, serialized


def write_bundle(output, identity, files, check=False):
    root = Path(output)
    require(root.is_absolute(), "profiles_output_dir must be absolute")
    require(not root.is_symlink(), "profiles_output_dir cannot be a symlink")
    require(not (root / "versions").is_symlink(), "versions path cannot be a symlink")
    require(not (root / "candidate").exists() or (root / "candidate").is_symlink(), "candidate path must be an owned symlink")
    target = root / "versions" / identity
    if target.exists():
        require(target.is_dir() and not target.is_symlink(), "bundle version path is unsafe")
        require(all((target / name).is_file() and not (target / name).is_symlink() and (target / name).read_text() == content for name, content in files.items()), "immutable bundle has changed")
    changed = not target.exists() or not (root / "candidate").is_symlink() or os.readlink(root / "candidate") != "versions/" + identity
    if check or not changed:
        return changed
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    versions = root / "versions"
    require(not versions.is_symlink(), "versions path cannot be a symlink")
    versions.mkdir(mode=0o700, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".candidate-", dir=root))
    try:
        for name, content in files.items():
            path = staging / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o600)
        if not target.exists():
            os.rename(staging, target)
        link = staging.with_name(staging.name + "-link")
        os.symlink("versions/" + identity, link)
        os.replace(link, root / "candidate")
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return True

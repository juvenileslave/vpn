"""Controller-side validation helpers for the ``base`` role.

All checks run before the role mutates a host. Error messages never include
key material or addresses, only the offending variable path.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import struct

# Public key algorithms accepted for administrative access.
ALLOWED_KEY_TYPES = frozenset({
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
})
# Every algorithm name that may appear in an existing authorized_keys line.
KNOWN_KEY_TYPES = ALLOWED_KEY_TYPES | {"ssh-dss"}
MIN_RSA_BITS = 3072
# Trusted SSH networks broader than this are refused as unsafe.
MIN_PREFIX = {4: 8, 6: 32}

USER_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
RESERVED_USERS = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "nobody",
    "sshd", "systemd-network", "systemd-resolve", "messagebus", "_apt",
})
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
ORIGIN_PATTERN = re.compile(r'^[^";\s\\]+$')
SWAP_FILE = re.compile(r"^/[A-Za-z0-9._/-]+$")
LISTENER = re.compile(r"^(tcp|udp)/([0-9]{1,5})$")
USER_FIELDS = {"name", "authorized_keys", "sudo"}
PORT_FIELDS = {"proto", "port"}
SOURCE_PORT_FIELDS = PORT_FIELDS | {"source_cidrs"}


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _read_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise ValueError("truncated")
    (length,) = struct.unpack(">I", blob[offset:offset + 4])
    end = offset + 4 + length
    if end > len(blob):
        raise ValueError("truncated")
    return blob[offset + 4:end], end


def public_key_error(line) -> str | None:
    """Return a reason why ``line`` is not an acceptable public key, or None."""
    if not isinstance(line, str):
        return "должен быть строкой"
    if any(ch in line for ch in "\r\n\0"):
        return "должен занимать одну строку"
    if "PRIVATE KEY" in line:
        return "похож на приватный ключ"
    parts = line.strip().split(None, 2)
    if len(parts) < 2:
        return "ожидается формат '<тип> <base64> [комментарий]'"
    key_type, body = parts[0], parts[1]
    if key_type not in ALLOWED_KEY_TYPES:
        return "неподдерживаемый тип ключа или опции authorized_keys"
    try:
        blob = base64.b64decode(body, validate=True)
        inner_type, offset = _read_string(blob, 0)
        if inner_type.decode("ascii") != key_type:
            return "тип в теле ключа не совпадает с заявленным"
        if key_type == "ssh-rsa":
            _exponent, offset = _read_string(blob, offset)
            modulus, offset = _read_string(blob, offset)
            if int.from_bytes(modulus, "big").bit_length() < MIN_RSA_BITS:
                return f"RSA-ключ короче {MIN_RSA_BITS} бит"
        elif key_type == "ssh-ed25519":
            point, offset = _read_string(blob, offset)
            if len(point) != 32:
                return "некорректный ed25519-ключ"
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return "тело ключа не является корректным base64 SSH-ключом"
    return None


def _key_body(line: str) -> str | None:
    tokens = line.split()
    for index, token in enumerate(tokens[:-1]):
        if token in KNOWN_KEY_TYPES:
            return tokens[index + 1]
    return None


def missing_keys(existing_text, keys) -> list[str]:
    """Keys whose base64 body is absent from an authorized_keys text.

    Existing lines (including their options and comments) are never rewritten.
    """
    present = set()
    for line in (existing_text or "").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            body = _key_body(stripped)
            if body:
                present.add(body)
    result = []
    for key in keys or []:
        body = key.strip().split()[1]
        if body not in present:
            present.add(body)
            result.append(key.strip())
    return result


def cidr_error(value) -> str | None:
    if not isinstance(value, str) or "/" not in value:
        return "ожидается CIDR с явной длиной префикса"
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return "некорректный CIDR или установлены биты хоста"
    if network.prefixlen < MIN_PREFIX[network.version]:
        return (f"слишком широкая сеть: префикс короче /{MIN_PREFIX[network.version]}"
                f" для IPv{network.version}")
    if (network.is_multicast or network.is_unspecified or network.is_loopback
            or network.network_address.is_unspecified):
        return "multicast, loopback и unspecified сети недопустимы"
    if network.version == 6 and network.network_address.ipv4_mapped is not None:
        return "IPv4-mapped IPv6 недопустим, укажите IPv4 CIDR"
    return None


def source_cidr_error(value) -> str | None:
    """Source ACLs may declare the exact colocated loopback control plane."""
    reason = cidr_error(value)
    if reason and isinstance(value, str) and "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            return reason
        if str(network) in ("127.0.0.1/32", "::1/128"):
            return None
    return reason


def split_cidrs(cidrs) -> dict:
    """Normalized CIDRs grouped by family for the nftables template."""
    result = {"v4": [], "v6": []}
    for value in cidrs or []:
        network = ipaddress.ip_network(value, strict=True)
        family = "v4" if network.version == 4 else "v6"
        if str(network) not in result[family]:
            result[family].append(str(network))
    return result


def _normalize_address(address: str):
    address = address.strip().strip("[]").split("%", 1)[0]
    parsed = ipaddress.ip_address(address)
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def ssh_source_allowed(address, cidrs) -> bool:
    """Whether the current SSH client address survives the firewall."""
    parsed = _normalize_address(address)
    if parsed.is_loopback:
        return True
    return any(parsed in ipaddress.ip_network(cidr, strict=True) for cidr in cidrs or [])


def _parse_listeners(ss_output: str) -> set[tuple[str, int]]:
    listeners = set()
    for line in (ss_output or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in {"tcp", "udp"}:
            continue
        host, _, port = fields[4].rpartition(":")
        if not port.isdigit():
            continue
        if host not in {"*", "0.0.0.0", "[::]", "::"}:
            try:
                if _normalize_address(host).is_loopback:
                    continue
            except ValueError:
                pass
        listeners.add((fields[0], int(port)))
    return listeners


def uncovered_listeners(ss_output, ssh_port, vpn_ports, acknowledged,
                        allow_dhcpv6_client=True, source_ports=None) -> list[str]:
    """Non-loopback listeners that the firewall would block unexpectedly."""
    covered = {("tcp", int(ssh_port))}
    covered |= {(item["proto"], int(item["port"])) for item in vpn_ports or []}
    covered |= {(item["proto"], item["port"]) for item in source_ports or []}
    # DHCPv4 replies arrive as established traffic or through packet sockets.
    covered.add(("udp", 68))
    if allow_dhcpv6_client:
        covered.add(("udp", 546))
    for item in acknowledged or []:
        proto, port = item.split("/", 1)
        covered.add((proto, int(port)))
    return sorted(f"{proto}/{port}" for proto, port in _parse_listeners(ss_output) - covered)


def sshd_effective(sshd_t_output) -> dict:
    """Parse ``sshd -T`` output into lists of values per lower-case keyword."""
    result: dict[str, list[str]] = {}
    for line in (sshd_t_output or "").splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            result.setdefault(key.lower(), []).append(value.strip())
    return result


def _check_bool(errors, cfg, key):
    if not isinstance(cfg.get(key), bool):
        errors.append(f"{key}: ожидается true или false")


def _admin_errors(errors, users):
    if not isinstance(users, list):
        errors.append("base_admin_users: ожидается список")
        return []
    names = []
    for index, user in enumerate(users):
        path = f"base_admin_users[{index}]"
        if not isinstance(user, dict):
            errors.append(f"{path}: ожидается mapping")
            continue
        unknown = set(user) - USER_FIELDS
        if unknown:
            errors.append(f"{path}: неизвестные поля {sorted(unknown)}")
        name = user.get("name")
        if not isinstance(name, str) or not USER_NAME.fullmatch(name):
            errors.append(f"{path}.name: недопустимое имя пользователя")
        elif name in RESERVED_USERS:
            errors.append(f"{path}.name: системное имя недопустимо")
        elif name in names:
            errors.append(f"{path}.name: повтор имени")
        else:
            names.append(name)
        if "sudo" in user and not isinstance(user["sudo"], bool):
            errors.append(f"{path}.sudo: ожидается true или false")
        keys = user.get("authorized_keys", [])
        if not isinstance(keys, list):
            errors.append(f"{path}.authorized_keys: ожидается список")
            continue
        for key_index, key in enumerate(keys):
            reason = public_key_error(key)
            if reason:
                errors.append(f"{path}.authorized_keys[{key_index}]: {reason}")
    return names


def input_errors(cfg) -> list[str]:
    """Validate the complete role input; an empty list means safe to proceed."""
    errors: list[str] = []
    for key in ("base_ssh_enabled", "base_firewall_enabled", "base_chrony_enabled",
                "base_unattended_upgrades_enabled", "base_bbr_enabled",
                "base_swap_enabled", "base_admin_sudo_nopasswd",
                "base_firewall_allow_icmp_echo", "base_firewall_allow_dhcpv6_client"):
        _check_bool(errors, cfg, key)

    users = cfg.get("base_admin_users")
    _admin_errors(errors, users)

    ssh_port = cfg.get("base_ssh_port")
    if not _is_int(ssh_port) or not 1 <= ssh_port <= 65535:
        errors.append("base_ssh_port: ожидается целое 1–65535")
        ssh_port = None
    if cfg.get("base_ssh_permit_root_login") not in ("no", "prohibit-password"):
        errors.append("base_ssh_permit_root_login: допустимо 'no' или 'prohibit-password'")

    if cfg.get("base_ssh_enabled") is True:
        usable = [
            user for user in users or []
            if isinstance(user, dict) and user.get("sudo", True) is True
            and user.get("authorized_keys")
        ]
        if not usable:
            errors.append("base_ssh_enabled: нужен хотя бы один администратор с sudo "
                          "и непустым authorized_keys")

    cidrs = cfg.get("base_ssh_trusted_cidrs")
    if not isinstance(cidrs, list):
        errors.append("base_ssh_trusted_cidrs: ожидается список")
        cidrs = []
    for index, cidr in enumerate(cidrs):
        reason = cidr_error(cidr)
        if reason:
            errors.append(f"base_ssh_trusted_cidrs[{index}]: {reason}")

    ports = cfg.get("base_firewall_vpn_ports")
    if not isinstance(ports, list):
        errors.append("base_firewall_vpn_ports: ожидается список")
        ports = []
    seen = set()
    for index, item in enumerate(ports):
        path = f"base_firewall_vpn_ports[{index}]"
        if not isinstance(item, dict) or set(item) != PORT_FIELDS:
            errors.append(f"{path}: ожидается mapping с полями proto и port")
            continue
        if not isinstance(item["proto"], str) or item["proto"] not in ("tcp", "udp"):
            errors.append(f"{path}.proto: допустимо tcp или udp")
            continue
        if not _is_int(item["port"]) or not 1 <= item["port"] <= 65535:
            errors.append(f"{path}.port: ожидается целое 1–65535")
            continue
        if item["proto"] == "tcp" and item["port"] == ssh_port:
            errors.append(f"{path}: SSH-порт нельзя открывать как публичный VPN-порт")
        if (item["proto"], item["port"]) in seen:
            errors.append(f"{path}: повтор порта")
        seen.add((item["proto"], item["port"]))

    source_ports = cfg.get("base_firewall_source_ports", [])
    if not isinstance(source_ports, list):
        errors.append("base_firewall_source_ports: ожидается список")
        source_ports = []
    for index, item in enumerate(source_ports):
        path = f"base_firewall_source_ports[{index}]"
        if not isinstance(item, dict) or set(item) != SOURCE_PORT_FIELDS:
            errors.append(f"{path}: ожидается mapping с полями proto, port и source_cidrs")
            continue
        proto, port = item["proto"], item["port"]
        valid_proto = isinstance(proto, str) and proto in ("tcp", "udp")
        valid_port = _is_int(port) and 1 <= port <= 65535
        if not valid_proto:
            errors.append(f"{path}.proto: допустимо tcp или udp")
        if not valid_port:
            errors.append(f"{path}.port: ожидается целое 1–65535")
        if valid_proto and valid_port:
            if proto == "tcp" and port == ssh_port:
                errors.append(f"{path}: SSH регулируется только base_ssh_trusted_cidrs")
            if proto == "udp" and port == 546 and cfg.get("base_firewall_allow_dhcpv6_client") is True:
                errors.append(f"{path}: UDP/546 несовместим с base_firewall_allow_dhcpv6_client=true")
            if (proto, port) in seen:
                errors.append(f"{path}: повтор или конфликт с публичным портом")
            seen.add((proto, port))
        sources = item["source_cidrs"]
        if not isinstance(sources, list) or not sources:
            errors.append(f"{path}.source_cidrs: ожидается непустой список CIDR")
            continue
        normalized = set()
        for source_index, source in enumerate(sources):
            source_path = f"{path}.source_cidrs[{source_index}]"
            reason = source_cidr_error(source)
            if reason:
                errors.append(f"{source_path}: {reason}")
                continue
            network = ipaddress.ip_network(source, strict=True)
            if str(network) in normalized:
                errors.append(f"{source_path}: повтор CIDR")
            normalized.add(str(network))

    acknowledged = cfg.get("base_firewall_acknowledged_closed_ports")
    if not isinstance(acknowledged, list) or not all(
        isinstance(item, str) and LISTENER.fullmatch(item)
        and 1 <= int(item.split("/")[1]) <= 65535 for item in acknowledged
    ):
        errors.append("base_firewall_acknowledged_closed_ports: ожидается список 'tcp/N' или 'udp/N'")

    if cfg.get("base_firewall_enabled") is True and not cidrs:
        errors.append("base_firewall_enabled: задайте непустой base_ssh_trusted_cidrs")

    pools = cfg.get("base_chrony_pools")
    if not isinstance(pools, list) or not all(
        isinstance(pool, str) and HOSTNAME.fullmatch(pool) for pool in pools
    ):
        errors.append("base_chrony_pools: ожидается список DNS-имён")

    patterns = cfg.get("base_unattended_origins_patterns")
    if not isinstance(patterns, list) or not patterns or not all(
        isinstance(item, str) and ORIGIN_PATTERN.fullmatch(item) for item in patterns
    ):
        errors.append("base_unattended_origins_patterns: ожидается непустой список "
                      "шаблонов без кавычек, пробелов и ';'")

    if not isinstance(cfg.get("base_bbr_qdisc"), str) or cfg["base_bbr_qdisc"] not in ("fq", ""):
        errors.append("base_bbr_qdisc: допустимо 'fq' или пустая строка")

    swap_file = cfg.get("base_swap_file")
    if (not isinstance(swap_file, str) or not SWAP_FILE.fullmatch(swap_file)
            or swap_file.endswith("/") or {".", ".."} & set(swap_file.split("/"))):
        errors.append("base_swap_file: ожидается абсолютный путь к файлу")
    size = cfg.get("base_swap_size_mb")
    if not _is_int(size) or not 64 <= size <= 65536:
        errors.append("base_swap_size_mb: ожидается целое 64–65536")
    return errors


class FilterModule:
    def filters(self):
        return {
            "vpn_base_input_errors": input_errors,
            "vpn_base_missing_keys": missing_keys,
            "vpn_base_split_cidrs": split_cidrs,
            "vpn_base_ssh_source_allowed": ssh_source_allowed,
            "vpn_base_uncovered_listeners": uncovered_listeners,
            "vpn_base_sshd_effective": sshd_effective,
        }

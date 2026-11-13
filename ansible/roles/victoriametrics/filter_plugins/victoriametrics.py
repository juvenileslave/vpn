"""Validation helpers for the victoriametrics role.

Error messages never include secret values. The ACL filter mirrors the
accepted remnawave_node semantics: a non-loopback listen address is allowed
only with an exact source rule in the base role's firewall contract.
"""

from __future__ import annotations

import ipaddress
import re

from ansible.errors import AnsibleFilterError

HOST_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
# Source ACLs and non-loopback listen addresses stay inside private space;
# TEST-NET documentation ranges are public on real hosts.
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def _is_private(address: object) -> bool:
    return any(
        address.version == network.version and address in network
        for network in PRIVATE_NETWORKS
    )


def victoriametrics_ip(value: object) -> dict[str, object]:
    """Return the canonical form of a literal unicast IP address or fail."""
    if not isinstance(value, str) or "%" in value:
        raise AnsibleFilterError(
            "victoriametrics_listen_address must be a literal IPv4 or IPv6 address "
            "without brackets, port or zone index"
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AnsibleFilterError(
            "victoriametrics_listen_address must be a literal IPv4 or IPv6 address "
            "without brackets, port or zone index"
        ) from None
    # A wildcard would expose the query API on every interface.
    if address.is_unspecified or address.is_multicast:
        raise AnsibleFilterError(
            "victoriametrics_listen_address must be a specific unicast address, "
            "not a wildcard or multicast address"
        )
    return {
        "address": address.compressed,
        "version": address.version,
        "loopback": address.is_loopback,
        "private": _is_private(address),
    }


def _networks(values: object) -> list[ipaddress._BaseNetwork]:
    if not isinstance(values, list):
        raise ValueError("not a list")
    return [ipaddress.ip_network(str(value), strict=True) for value in values]


def victoriametrics_acl_ok(
    listen: dict[str, object],
    port: object,
    sources: object,
    source_ports: object,
    vpn_ports: object,
    ssh_port: object,
    firewall_enabled: object,
) -> bool:
    """True when the declared query API ACL matches the accepted base contract.

    Loopback needs no ACL and forbids one. A non-loopback listen address must
    be private (RFC 1918 / ULA), the base firewall must be enabled, the port
    must not collide with SSH or VPN ports, and exactly one tcp
    `base_firewall_source_ports` rule must carry exactly the declared sources
    of the same address family.
    """
    try:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return False
        if port == ssh_port:
            return False
        if any(rule.get("port") == port for rule in vpn_ports or []):
            return False
        if listen["loopback"]:
            # An ACL on a loopback listener would be misleading dead config.
            return sources in ([], None)
        if firewall_enabled not in (True, "true", "True", "yes"):
            return False
        if not listen["private"]:
            return False
        if not isinstance(sources, list) or not sources:
            return False
        networks = _networks(sources)
        if len(set(networks)) != len(networks):
            return False
        for network in networks:
            # A wider source ACL would silently broaden query API access.
            if network.prefixlen not in (32, 128):
                return False
            if network.is_multicast or network.is_unspecified or network.is_loopback:
                return False
            if not _is_private(network.network_address):
                return False
            if network.version != listen["version"]:
                return False
        matches = [
            rule for rule in source_ports or [] if rule.get("port") == port
        ]
        if len(matches) != 1 or matches[0].get("proto") != "tcp":
            return False
        declared = _networks(matches[0].get("source_cidrs"))
        return sorted(str(network) for network in declared) == sorted(
            str(network) for network in networks
        )
    except (ValueError, TypeError, AttributeError, KeyError):
        return False


def victoriametrics_targets(nodes: object, port: object) -> list[str]:
    """Render host:port scrape targets for node_exporter of the given nodes."""
    if not isinstance(nodes, list):
        raise AnsibleFilterError("victoriametrics_scrape_nodes must be a list of host names")
    if isinstance(port, bool) or not isinstance(port, int):
        raise AnsibleFilterError("the node_exporter port must be an integer")
    if not 1 <= port <= 65535:
        raise AnsibleFilterError("the node_exporter port must be 1-65535")
    targets: list[str] = []
    for node in nodes:
        if not isinstance(node, str) or not HOST_NAME.fullmatch(node):
            raise AnsibleFilterError(
                "victoriametrics_scrape_nodes must be a list of DNS host names; "
                f"got {node!r}"
            )
        targets.append(f"{node}:{port}")
    return targets


def victoriametrics_panel_target(url: object) -> dict[str, str]:
    """Split a panel metrics URL into scheme, hostport and metrics path."""
    if not isinstance(url, str):
        raise AnsibleFilterError("the panel metrics url must be a string")
    scheme, separator, remainder = url.partition("://")
    if not separator or scheme not in ("http", "https"):
        raise AnsibleFilterError("the panel metrics url must be an http(s) URL")
    hostport, _, path = remainder.partition("/")
    if not hostport:
        raise AnsibleFilterError("the panel metrics url has no host")
    return {
        "scheme": scheme,
        "hostport": hostport,
        "path": "/" + path if path else "/metrics",
    }


def victoriametrics_duration_ok(value: object) -> bool:
    """True for a retention value VictoriaMetrics accepts with an explicit unit.

    Bare numbers mean months in VictoriaMetrics; the role rejects them so the
    accepted default (30 days) can never silently degrade to a month count.
    """
    if not isinstance(value, str) or not value:
        return False
    if value.isdigit():
        return False
    number, suffix = value[:-1], value[-1]
    if suffix not in "shdwMy":
        return False
    try:
        amount = float(number)
    except ValueError:
        return False
    return amount > 0


class FilterModule:
    def filters(self) -> dict[str, object]:
        return {
            "victoriametrics_ip": victoriametrics_ip,
            "victoriametrics_acl_ok": victoriametrics_acl_ok,
            "victoriametrics_targets": victoriametrics_targets,
            "victoriametrics_panel_target": victoriametrics_panel_target,
            "victoriametrics_duration_ok": victoriametrics_duration_ok,
        }

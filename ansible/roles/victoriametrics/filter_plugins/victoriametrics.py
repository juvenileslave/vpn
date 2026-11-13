"""Validation helpers for the victoriametrics role.

Error messages never include secret values.
"""

from __future__ import annotations

import ipaddress
import re

from ansible.errors import AnsibleFilterError

HOST_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


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
        "private": address.is_private,
    }


def victoriametrics_sources_ok(listen: dict[str, object], sources: object) -> bool:
    """True when the source ACL matches the listen address policy.

    A non-loopback listen address requires an explicit non-empty list of exact
    private /32 or /128 source CIDRs; loopback needs no ACL at all.
    """
    if listen["loopback"]:
        return True
    if not isinstance(sources, list) or not sources:
        return False
    try:
        networks = [ipaddress.ip_network(str(item), strict=True) for item in sources]
    except (ValueError, TypeError):
        return False
    if len(set(networks)) != len(networks):
        return False
    for network in networks:
        # A wider source ACL would silently broaden query API access.
        if network.prefixlen not in (32, 128):
            return False
        if network.is_multicast or network.is_unspecified or network.is_loopback:
            return False
        # TEST-NET documentation ranges are public on real hosts; require
        # RFC 1918 / ULA private space (matching base-role source ports).
        if not (
            network.network_address in ipaddress.ip_network("10.0.0.0/8")
            or network.network_address in ipaddress.ip_network("172.16.0.0/12")
            or network.network_address in ipaddress.ip_network("192.168.0.0/16")
            or network.network_address in ipaddress.ip_network("fc00::/7")
        ):
            return False
    return True


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
            "victoriametrics_sources_ok": victoriametrics_sources_ok,
            "victoriametrics_targets": victoriametrics_targets,
            "victoriametrics_panel_target": victoriametrics_panel_target,
            "victoriametrics_duration_ok": victoriametrics_duration_ok,
        }

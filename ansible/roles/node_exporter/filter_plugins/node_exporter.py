"""Validation of the node_exporter listen address."""

from __future__ import annotations

import ipaddress

from ansible.errors import AnsibleFilterError


def node_exporter_ip(value: object) -> dict[str, object]:
    """Return the canonical form of a literal unicast IP address or fail."""
    if not isinstance(value, str) or "%" in value:
        raise AnsibleFilterError(
            "node_exporter_listen_address must be a literal IPv4 or IPv6 address "
            "without brackets, port or zone index"
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AnsibleFilterError(
            "node_exporter_listen_address must be a literal IPv4 or IPv6 address "
            "without brackets, port or zone index"
        ) from None
    # A wildcard would expose the exporter on every interface.
    if address.is_unspecified or address.is_multicast:
        raise AnsibleFilterError(
            "node_exporter_listen_address must be a specific unicast address, "
            "not a wildcard or multicast address"
        )
    return {
        "address": address.compressed,
        "version": address.version,
        "loopback": address.is_loopback,
    }


class FilterModule:
    def filters(self) -> dict[str, object]:
        return {"node_exporter_ip": node_exporter_ip}

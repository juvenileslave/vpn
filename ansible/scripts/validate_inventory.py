"""Validate the Ansible inventory contract of the double-hop VPN topology.

The checks are static: the script reads YAML files only and never connects
to any host. Example-only rules apply when the inventory file lives in a
directory named ``example``.
"""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import re
import sys
from typing import Any, Callable

import yaml


ROLE_GROUPS = {"exit": "exit", "relay": "relay", "cp": "control_plane"}
ENUMS = {
    "cp_placement": ("exit", "dedicated"),
    "client_family": ("v4", "dual"),
    "s2s_family": ("v6_prefer", "v4_only", "v6_only"),
    "egress_family": ("v4_prefer", "v6_prefer", "v4_only"),
    "slot_fanout": ("sni", "ports"),
    "xhttp_mode": ("auto", "packet-up", "stream-up", "stream-one"),
}
COMMON_KEYS = (
    "cp_placement", "client_family", "s2s_family", "egress_family",
    "egress_slots", "slot_fanout", "node_port_allow", "reality_sni",
    "reality_target", "xhttp_path", "xhttp_mode", "image_tags",
)
ADDRESS_KEYS = ("public_ipv4", "public_ipv6")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
EGRESS_SLOTS_RANGE = range(1, 7)
EXAMPLE_SNI_SUFFIX = ".example.com"
YAML_SUFFIXES = (".yml", ".yaml")
HOST_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
DNS_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
HOST_PORT = re.compile(r"\[(?P<ipv6>[^\]]+)\]:(?P<port6>[0-9]+)|(?P<host>[^:\[\]]+):(?P<port>[0-9]+)")

# A layered variable keeps the location it came from for error messages.
Located = tuple[Any, str]


class Inventory:
    def __init__(self, path: Path, example: bool) -> None:
        self.path = path
        self.root = path.parent
        self.example = example
        self.errors: list[str] = []
        self.groups: dict[str, dict[str, dict[str, Located]]] = {}
        self.group_inline: dict[str, dict[str, Located]] = {}
        self.group_files: dict[str, dict[str, Located]] = {}
        self.host_files: dict[str, dict[str, Located]] = {}

    def error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)

    def label(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            return str(path)

    def load_yaml(self, path: Path) -> Any:
        try:
            return yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            self.error(f"{self.label(path)}: cannot read file: {exc.strerror}")
        except UnicodeDecodeError:
            self.error(f"{self.label(path)}: file is not UTF-8")
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f":{mark.line + 1}" if mark is not None else ""
            self.error(f"{self.label(path)}{where}: invalid YAML")
        return None

    def variables(self, data: Any, origin: str) -> dict[str, Located]:
        if data is None:
            return {}
        if not isinstance(data, dict):
            self.error(f"{origin.rstrip(':')}: expected a mapping of variables")
            return {}
        result = {}
        for key, value in data.items():
            if not isinstance(key, str):
                self.error(f"{origin}: variable names must be strings")
                continue
            separator = " " if origin.endswith(":") else "."
            result[key] = (value, f"{origin}{separator}{key}")
        return result

    # --- loading -----------------------------------------------------------

    def load(self) -> None:
        if not self.path.is_file():
            self.error(f"{self.label(self.path)}: inventory file not found")
            return
        self.load_hosts_file()
        self.load_vars_directory("group_vars", set(ROLE_GROUPS) | {"all"}, self.group_files)
        known_hosts = {host for hosts in self.groups.values() for host in hosts}
        self.load_vars_directory("host_vars", known_hosts, self.host_files)

    def load_hosts_file(self) -> None:
        name = self.label(self.path)
        data = self.load_yaml(self.path)
        if data is None:
            if not self.errors:
                self.error(f"{name}: inventory is empty")
            return
        if not isinstance(data, dict) or set(data) != {"all"}:
            self.error(f"{name}: top level must contain only the 'all' group")
            return
        top = data["all"]
        if not isinstance(top, dict):
            self.error(f"{name}: all: expected a mapping")
            return
        for key in sorted(set(top) - {"children", "vars"}, key=str):
            self.error(f"{name}: all.{key}: not allowed; hosts belong to exit, relay or cp")
        self.group_inline["all"] = self.variables(top.get("vars"), f"{name}: all.vars")

        children = top.get("children")
        if not isinstance(children, dict):
            self.error(f"{name}: all.children: expected groups {', '.join(ROLE_GROUPS)}")
            return
        for group in sorted(set(children) - set(ROLE_GROUPS), key=str):
            self.error(f"{name}: all.children.{group}: unknown group; allowed: {', '.join(ROLE_GROUPS)}")
        seen: dict[str, str] = {}
        for group in ROLE_GROUPS:
            origin = f"{name}: all.children.{group}"
            if group not in children:
                self.error(f"{origin}: required group is missing")
                continue
            self.groups[group] = self.load_group(children[group], origin)
            for host in self.groups[group]:
                if host in seen:
                    self.error(f"{origin}.hosts.{host}: host is already in group {seen[host]}")
                seen[host] = group

    def load_group(self, data: Any, origin: str) -> dict[str, dict[str, Located]]:
        group = origin.rsplit(".", 1)[1]
        if data is None:
            data = {}
        if not isinstance(data, dict):
            self.error(f"{origin}: expected a mapping")
            return {}
        for key in sorted(set(data) - {"hosts", "vars"}, key=str):
            self.error(f"{origin}.{key}: not allowed; use only hosts and vars")
        self.group_inline[group] = self.variables(data.get("vars"), f"{origin}.vars")
        hosts = data.get("hosts") or {}
        if not isinstance(hosts, dict):
            self.error(f"{origin}.hosts: expected a mapping of hosts")
            return {}
        result = {}
        for host, host_vars in hosts.items():
            if not isinstance(host, str) or not HOST_NAME.fullmatch(host):
                self.error(f"{origin}.hosts: invalid host name {host!r}")
                continue
            result[host] = self.variables(host_vars, f"{origin}.hosts.{host}")
        return result

    def load_vars_directory(self, directory: str, allowed: set[str], target: dict[str, dict[str, Located]]) -> None:
        base = self.root / directory
        if not base.exists():
            return
        if not base.is_dir():
            self.error(f"{self.label(base)}: expected a directory")
            return
        for entry in sorted(base.iterdir()):
            label = self.label(entry)
            if not entry.is_file() or entry.suffix not in YAML_SUFFIXES:
                self.error(f"{label}: only <name>.yml files are supported")
                continue
            if entry.stem not in allowed:
                self.error(f"{label}: '{entry.stem}' does not match any {'group' if directory == 'group_vars' else 'host'} in the inventory")
                continue
            if entry.stem in target:
                self.error(f"{label}: duplicate variables file for '{entry.stem}'")
                continue
            target[entry.stem] = self.variables(self.load_yaml(entry), f"{label}:")

    # --- effective variables ----------------------------------------------

    def effective(self, group: str, host: str) -> dict[str, Located]:
        """Merge layers in ansible-core inventory precedence order."""
        inline = self.groups[group][host]
        file_vars = self.host_files.get(host, {})
        for key, (value, origin) in inline.items():
            if key in file_vars and file_vars[key][0] != value:
                self.error(f"{file_vars[key][1]}: conflicts with {origin}")
        merged: dict[str, Located] = {}
        for layer in (
            self.group_inline.get("all", {}),
            self.group_inline.get(group, {}),
            self.group_files.get("all", {}),
            self.group_files.get(group, {}),
            inline,
            file_vars,
        ):
            merged.update(layer)
        return merged

    # --- validation --------------------------------------------------------

    def validate(self) -> None:
        self.load()
        if self.errors or len(self.groups) != len(ROLE_GROUPS):
            return
        addresses: dict[Any, str] = {}
        placements: set[Any] = set()
        for group, hosts in self.groups.items():
            for host in hosts:
                values = self.effective(group, host)
                self.validate_host(group, host, values, addresses)
                self.validate_common(host, values)
                if "cp_placement" in values:
                    placements.add(self.placement_value(values["cp_placement"]))
        self.validate_topology(placements)

    def placement_value(self, located: Located) -> Any:
        value, origin = located
        all_files = (self.label(self.root / "group_vars" / f"all{suffix}") for suffix in YAML_SUFFIXES)
        if not origin.startswith(tuple(f"{name}:" for name in all_files)) and ": all.vars." not in origin:
            self.error(f"{origin}: cp_placement must be set only in group_vars/all")
        return value

    def validate_host(self, group: str, host: str, values: dict[str, Located], addresses: dict[Any, str]) -> None:
        where = f"host {host}"
        role = values.get("node_role")
        if role is None:
            self.error(f"{where}: node_role is missing")
        elif role[0] != ROLE_GROUPS[group]:
            self.error(f"{role[1]}: node_role must be '{ROLE_GROUPS[group]}' for group {group}")

        parsed: dict[str, Any] = {}
        for key, family, version in zip(ADDRESS_KEYS, (ipaddress.IPv4Address, ipaddress.IPv6Address), (4, 6)):
            if key not in values:
                self.error(f"{where}: {key} is missing")
                continue
            value, origin = values[key]
            try:
                address = family(value) if isinstance(value, str) else None
            except ValueError:
                address = None
            if address is None:
                self.error(f"{origin}: must be an IPv{version} address")
                continue
            parsed[key] = address
            if self.example and not in_networks(address, DOCUMENTATION_NETWORKS):
                self.error(f"{origin}: example address is outside the documentation ranges")
            if address in addresses:
                self.error(f"{origin}: duplicates the address in {addresses[address]}")
            else:
                addresses[address] = origin

        if "ansible_host" not in values:
            self.error(f"{where}: ansible_host is missing")
            return
        value, origin = values["ansible_host"]
        if not isinstance(value, str) or not value.strip():
            self.error(f"{origin}: must be a non-empty string")
        elif self.example and (
            "public_ipv4" not in parsed or ip_or_none(value) != parsed["public_ipv4"]
        ):
            self.error(f"{origin}: example ansible_host must equal the documentation public_ipv4")

    def validate_common(self, host: str, values: dict[str, Located]) -> None:
        checks: dict[str, Callable[[Any], str | None]] = {
            "egress_slots": check_egress_slots,
            "node_port_allow": self.check_node_port_allow,
            "reality_sni": self.check_reality_sni,
            "reality_target": check_reality_target,
            "xhttp_path": check_xhttp_path,
            "image_tags": check_image_tags,
        }
        for key in COMMON_KEYS:
            if key not in values:
                self.error(f"host {host}: {key} is missing")
                continue
            value, origin = values[key]
            if key in ENUMS:
                problem = None if value in ENUMS[key] and isinstance(value, str) else (
                    f"must be one of {', '.join(ENUMS[key])}, got {value!r}"
                )
            else:
                problem = checks[key](value)
            if problem:
                self.error(f"{origin}: {problem}")

    def validate_topology(self, placements: set[Any]) -> None:
        name = self.label(self.path)
        exits, relays, cps = (list(self.groups[group]) for group in ROLE_GROUPS)
        if len(exits) != 1:
            self.error(f"{name}: group exit must contain exactly one host, found {len(exits)}")
        if len(relays) != 1:
            self.error(f"{name}: group relay must contain exactly one host, found {len(relays)}")
        if len(placements) != 1:
            return
        placement = next(iter(placements))
        if placement == "dedicated":
            if len(cps) != 1:
                self.error(f"{name}: cp_placement dedicated requires exactly one cp host, found {len(cps)}")
            elif cps[0] in exits:
                self.error(f"{name}: cp host must be distinct from the exit host")
        elif placement == "exit" and cps:
            self.error(f"{name}: cp_placement exit requires an empty cp group; the control plane runs on exit")

    def check_node_port_allow(self, value: Any) -> str | None:
        if not isinstance(value, list):
            return "must be a list of CIDRs"
        for index, item in enumerate(value):
            if not isinstance(item, str) or "/" not in item:
                return f"item {index}: must be a CIDR such as 192.0.2.0/24"
            try:
                network = ipaddress.ip_network(item, strict=True)
            except ValueError:
                return f"item {index}: invalid CIDR {item!r}"
            if self.example and not in_networks(network, DOCUMENTATION_NETWORKS + PRIVATE_NETWORKS):
                return f"item {index}: example CIDR must be in documentation or private ranges"
        return None

    def check_reality_sni(self, value: Any) -> str | None:
        if not is_dns_name(value, min_labels=2):
            return "must be a non-empty DNS name"
        if self.example and not value.lower().endswith(EXAMPLE_SNI_SUFFIX):
            return f"example SNI must end with {EXAMPLE_SNI_SUFFIX}"
        return None

    def summary(self) -> str:
        hosts = "; ".join(f"{group}: {', '.join(hosts) or '-'}" for group, hosts in self.groups.items())
        mode = "example" if self.example else "regular"
        return f"Inventory OK: {self.label(self.path)} ({mode}; {hosts})"


def in_networks(item: Any, networks: tuple[Any, ...]) -> bool:
    if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return any(item.version == net.version and item.subnet_of(net) for net in networks)
    return any(item in net for net in networks)


def ip_or_none(value: str) -> Any:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_dns_name(value: Any, min_labels: int = 1) -> bool:
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    labels = value.split(".")
    return (
        len(labels) >= min_labels
        and all(DNS_LABEL.fullmatch(label) for label in labels)
        and not labels[-1].isdigit()
    )


def check_egress_slots(value: Any) -> str | None:
    if type(value) is not int or value not in EGRESS_SLOTS_RANGE:
        return "must be an integer from 1 through 6"
    return None


def check_xhttp_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("/") or any(c.isspace() for c in value):
        return "must start with / and contain no whitespace"
    return None


def check_reality_target(value: Any) -> str | None:
    match = HOST_PORT.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return "must be host:port or [ipv6]:port"
    if match["ipv6"] is not None:
        host_ok = isinstance(ip_or_none(match["ipv6"]), ipaddress.IPv6Address)
        port = match["port6"]
    else:
        host_ok = ip_or_none(match["host"]) is not None or is_dns_name(match["host"])
        port = match["port"]
    if not host_ok:
        return "host part must be an IP address or DNS name"
    if not 1 <= int(port) <= 65535:
        return "port must be from 1 through 65535"
    return None


def check_image_tags(value: Any) -> str | None:
    if not isinstance(value, dict):
        return "must be a mapping"
    if not all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in value.items()):
        return "keys and values must be non-empty strings"
    return None


def validate(path: Path, example: bool | None = None) -> Inventory:
    inventory = Inventory(path, path.parent.name == "example" if example is None else example)
    inventory.validate()
    return inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inventory", required=True, type=Path, help="path to hosts.yml")
    args = parser.parse_args(argv)
    inventory = validate(args.inventory)
    if inventory.errors:
        print(f"Inventory invalid: {len(inventory.errors)} error(s)", file=sys.stderr)
        for message in inventory.errors:
            print(f"  - {message}", file=sys.stderr)
        return 1
    print(inventory.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

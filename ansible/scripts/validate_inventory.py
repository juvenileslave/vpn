"""Validate the Ansible inventory contract of the double-hop VPN topology.

The checks are static: the script reads YAML files only and never connects
to any host. Example-only rules apply when the inventory file lives in a
directory named ``example``.
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
from functools import lru_cache
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
    "xhttp_path", "xhttp_mode", "image_tags",
)
ADDRESS_KEYS = ("public_ipv4", "public_ipv6")
NODE_GROUPS = ("exit", "relay")
# Exactly one inventory layer owns each management/firewall decision.
AUTHORITY_KEYS = (
    "node_api_port", "node_port_allow", "base_firewall_enabled",
    "base_firewall_bootstrap_exception", "base_firewall_vpn_ports",
    "base_firewall_source_ports",
    # One publication authority and no separately declared duplicates.
    "subscription_public_host", "subscription_public_path",
    "cp_proxy_server_name", "cp_proxy_path_prefix", "cp_proxy_upstream",
    "remnawave_panel_sub_public_domain",
)
BOOTSTRAP_EXCEPTION_FIELDS = {"temporary", "source_cidrs"}
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
# Same contract as the cp_proxy role: lowercase DNS name, no wildcard/IP/port.
SUBSCRIPTION_HOST = re.compile(
    r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"
)
SUBSCRIPTION_PATH = re.compile(r"^/([A-Za-z0-9._~-]+/)+$")
SUBSCRIPTION_RESERVED = ("/api/", "/admin/", "/.well-known/")
# Managed-state snapshot schema used by --state/--write-expected.
STATE_SCHEMA = 1

# A layered variable keeps the location it came from for error messages.
Located = tuple[Any, str]


@lru_cache(maxsize=1)
def profile_contract() -> Any:
    """The accepted offline profile contract; one source for its defaults."""
    module_path = Path(__file__).resolve().parents[1] / "roles/profiles/module_utils/profile_bundle.py"
    spec = importlib.util.spec_from_file_location("vpn_profile_contract", module_path)
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    return contract


@lru_cache(maxsize=1)
def base_contract() -> Any:
    """The accepted base role validator; one source for SSH CIDR rules."""
    module_path = Path(__file__).resolve().parents[1] / "roles/base/filter_plugins/vpn_base.py"
    spec = importlib.util.spec_from_file_location("vpn_base_contract", module_path)
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    return contract


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
        self.placement: Any = None

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
        authority: dict[str, str] = {}
        for layer in (
            self.group_inline.get("all", {}),
            self.group_inline.get(group, {}),
            self.group_files.get("all", {}),
            self.group_files.get(group, {}),
            inline,
            file_vars,
        ):
            for key, (_value, origin) in layer.items():
                if key in AUTHORITY_KEYS:
                    if key in authority:
                        self.error(
                            f"{origin}: {key} must have one authority; also defined in {authority[key]}"
                        )
                    else:
                        authority[key] = origin
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
                self.validate_ssh_break_glass(host, values)
                self.validate_management(group, host, values)
                if "cp_placement" in values:
                    placement = self.placement_value(values["cp_placement"])
                    if isinstance(placement, str):
                        placements.add(placement)
        self.validate_topology(placements)
        self.validate_publication()
        self.validate_profiles()

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
        self.placement = placement

    def panel_layer(self) -> tuple[str, str] | None:
        """The single host that owns the panel and the subscription vhost."""
        if self.placement == "dedicated":
            hosts = list(self.groups.get("cp", {}))
            return ("cp", hosts[0]) if len(hosts) == 1 else None
        if self.placement == "exit":
            hosts = list(self.groups.get("exit", {}))
            return ("exit", hosts[0]) if len(hosts) == 1 else None
        return None

    def validate_publication(self) -> None:
        """One declared authority for the public subscription endpoint."""
        layer = self.panel_layer()
        if layer is None:
            return
        group, host = layer
        values = self.effective(group, host)
        where = f"host {host}"

        located = values.get("subscription_public_host")
        if located is None:
            self.error(f"{where}: subscription_public_host is required for the panel host")
        else:
            value, origin = located
            if not isinstance(value, str) or not SUBSCRIPTION_HOST.fullmatch(value):
                self.error(f"{origin}: must be a lowercase DNS name with a dot; no wildcard, IP or port")
            elif len(value) > 253:
                self.error(f"{origin}: must be at most 253 characters")
            elif self.example and not value.endswith(EXAMPLE_SNI_SUFFIX):
                self.error(f"{origin}: example subscription host must end with {EXAMPLE_SNI_SUFFIX}")

        located = values.get("subscription_public_path")
        if located is None:
            self.error(f"{where}: subscription_public_path is required for the panel host")
        else:
            value, origin = located
            if not isinstance(value, str) or not SUBSCRIPTION_PATH.fullmatch(value):
                self.error(f"{origin}: must look like /sub/ (starts and ends with '/', no whitespace)")
            elif any(segment in (".", "..") for segment in value.strip("/").split("/")):
                self.error(f"{origin}: dot segments are not allowed")
            elif any(reserved in value.lower() for reserved in SUBSCRIPTION_RESERVED):
                self.error(f"{origin}: must not expose /api/, /admin/ or /.well-known/")

        # The role defaults derive these values. A separate declaration would
        # become a second, undetected source of publication drift.
        derived_from = {
            "cp_proxy_upstream": "panel_bind:panel_port",
        }
        for key in ("cp_proxy_server_name", "cp_proxy_path_prefix",
                    "cp_proxy_upstream", "remnawave_panel_sub_public_domain"):
            located = values.get(key)
            if located is not None:
                source = derived_from.get(
                    key, "subscription_public_host/subscription_public_path"
                )
                self.error(f"{located[1]}: must be derived from {source}; "
                           "remove the duplicate declaration")

    def validate_ssh_break_glass(self, host: str, values: dict[str, Located]) -> None:
        """Every declared host must preserve an explicit direct SSH path."""
        where = f"host {host}"
        ssh_enabled = values.get("base_ssh_enabled")
        if ssh_enabled is None:
            if not self.example:
                self.error(
                    f"{where}: base_ssh_enabled is required and must be true "
                    "for direct SSH break-glass"
                )
        else:
            value, origin = ssh_enabled
            if not isinstance(value, bool):
                self.error(f"{origin}: must be true or false")
            elif not value:
                self.error(f"{origin}: base_ssh_enabled must be true for direct SSH break-glass")

        ssh_port_entry = values.get("base_ssh_port")
        ssh_port: int | None = None
        if ssh_port_entry is None:
            self.error(f"{where}: base_ssh_port is required")
        else:
            value, origin = ssh_port_entry
            if type(value) is not int or not 1 <= value <= 65535:
                self.error(f"{origin}: must be an integer port 1-65535")
            else:
                ssh_port = value

        ansible_port_entry = values.get("ansible_port")
        if ansible_port_entry is not None:
            ap_value, ap_origin = ansible_port_entry
            if type(ap_value) is not int or not 1 <= ap_value <= 65535:
                self.error(f"{ap_origin}: must be an integer port 1-65535")
            elif ssh_port is not None and ap_value != ssh_port:
                self.error(f"{ap_origin}: ansible_port must equal base_ssh_port")

        root_login = values.get("base_ssh_permit_root_login")
        if root_login is None:
            self.error(f"{where}: base_ssh_permit_root_login is required and must be 'no'")
        elif root_login[0] != "no":
            self.error(f"{root_login[1]}: base_ssh_permit_root_login must be 'no'")

        trusted = values.get("base_ssh_trusted_cidrs")
        if trusted is None:
            self.error(f"{where}: base_ssh_trusted_cidrs is required for direct SSH break-glass")
        else:
            cidrs, origin = trusted
            if not isinstance(cidrs, list):
                self.error(f"{origin}: must be a list of CIDRs")
            elif not cidrs:
                self.error(f"{origin}: must not be empty")
            else:
                ssh_cidr_error = base_contract().ssh_cidr_error
                seen: set[str] = set()
                for index, item in enumerate(cidrs):
                    problem = ssh_cidr_error(item)
                    if problem:
                        self.error(f"{origin}[{index}]: {problem}")
                        continue
                    network = ipaddress.ip_network(item, strict=True)
                    if self.example and not in_networks(network, DOCUMENTATION_NETWORKS + PRIVATE_NETWORKS):
                        self.error(f"{origin}[{index}]: example CIDR must be in documentation or private ranges")
                    normalized = str(network)
                    if normalized in seen:
                        self.error(f"{origin}[{index}]: duplicate CIDR")
                    seen.add(normalized)

        if ssh_port is not None:
            public = values.get("base_firewall_vpn_ports")
            if public is not None and isinstance(public[0], list):
                for index, item in enumerate(public[0]):
                    if isinstance(item, dict) and item.get("proto") == "tcp" and item.get("port") == ssh_port:
                        self.error(
                            f"{public[1]}[{index}]: base_ssh_port must not be declared as a public "
                            "base_firewall_vpn_ports listener"
                        )
            source_ports = values.get("base_firewall_source_ports")
            if source_ports is not None and isinstance(source_ports[0], list):
                for index, item in enumerate(source_ports[0]):
                    if isinstance(item, dict) and item.get("proto") == "tcp" and item.get("port") == ssh_port:
                        self.error(
                            f"{source_ports[1]}[{index}]: base_ssh_port is governed only by "
                            "base_ssh_trusted_cidrs, not base_firewall_source_ports"
                        )

    def validate_management(self, group: str, host: str, values: dict[str, Located]) -> None:
        where = f"host {host}"
        enabled = values.get("base_firewall_enabled")
        exception = values.get("base_firewall_bootstrap_exception")
        if enabled is None:
            self.error(f"{where}: base_firewall_enabled is required; declare true or an explicit "
                       "temporary base_firewall_bootstrap_exception")
        else:
            value, origin = enabled
            if not isinstance(value, bool):
                self.error(f"{origin}: must be true or false")
            elif value:
                if exception is not None:
                    self.error(f"{exception[1]}: must be absent when base_firewall_enabled is true")
            elif exception is None:
                self.error(f"{origin}: base_firewall_enabled=false is refused outside an explicit "
                           "temporary base_firewall_bootstrap_exception")
            else:
                self.validate_bootstrap_exception(values, exception)
        if group not in NODE_GROUPS:
            return

        api = values.get("node_api_port")
        api_port: int | None = None
        if api is None:
            self.error(f"{where}: node_api_port is required; there is no implicit 2222 fallback")
        else:
            value, origin = api
            if type(value) is not int or not 1 <= value <= 65535:
                self.error(f"{origin}: must be an integer port 1-65535")
            else:
                api_port = value
                if self.example and api_port == 2222:
                    self.error(f"{origin}: must not reuse the upstream example 2222; "
                               "declare the deployment's explicit management port")
        ssh = values.get("base_ssh_port")
        if api_port is not None and ssh is not None and type(ssh[0]) is int and api_port == ssh[0]:
            self.error(f"{api[1]}: node API port must differ from base_ssh_port")

        allow_networks: set[Any] | None = None
        allow = values.get("node_port_allow")
        if allow is None:
            self.error(f"{where}: node_port_allow is required")
        else:
            value, origin = allow
            if not isinstance(value, list):
                self.error(f"{origin}: must be a list of CIDRs")
            elif not value:
                self.error(f"{origin}: must not be empty")
            else:
                parsed = set()
                for item in value:
                    try:
                        parsed.add(ipaddress.ip_network(item, strict=True))
                    except (TypeError, ValueError):
                        pass
                if len(parsed) == len(value):
                    allow_networks = parsed
        placement = values.get("cp_placement")
        if (placement is not None and placement[0] == "dedicated"
                and allow_networks and all(network.is_loopback for network in allow_networks)):
            self.error(f"{allow[1]}: dedicated remote CP cannot use loopback-only management sources")

        public = values.get("base_firewall_vpn_ports")
        if api_port is not None:
            if public is None:
                self.error(f"{where}: base_firewall_vpn_ports is required")
            else:
                public_value, public_origin = public
                if not isinstance(public_value, list):
                    self.error(f"{public_origin}: must be a list")
                elif any(isinstance(item, dict) and item.get("port") == api_port
                         for item in public_value):
                    self.error(f"{where}: node_api_port must not be declared as a public "
                               "base_firewall_vpn_ports listener")

        rules = values.get("base_firewall_source_ports")
        if api_port is None:
            return
        if rules is None:
            self.error(f"{where}: base_firewall_source_ports is required")
            return
        rules_value, rules_origin = rules
        if not isinstance(rules_value, list):
            self.error(f"{rules_origin}: must be a list")
            return
        matches = [item for item in rules_value
                   if isinstance(item, dict) and item.get("port") == api_port]
        if len(matches) != 1:
            self.error(f"{where}: node_api_port requires exactly one base_firewall_source_ports "
                       f"rule, found {len(matches)}")
            return
        rule = matches[0]
        if rule.get("proto") != "tcp":
            self.error(f"{where}: node API base_firewall_source_ports rule must be tcp")
        sources = rule.get("source_cidrs")
        if not isinstance(sources, list) or not sources:
            self.error(f"{where}: node API source rule requires a nonempty source_cidrs list")
            return
        if allow_networks is not None:
            normalized = set()
            for item in sources:
                try:
                    normalized.add(ipaddress.ip_network(item, strict=True))
                except (TypeError, ValueError):
                    return
            if normalized != allow_networks:
                self.error(f"{where}: node API source_cidrs must equal node_port_allow")

    def validate_bootstrap_exception(self, values: dict[str, Located], located: Located) -> None:
        value, origin = located
        if not isinstance(value, dict) or set(value) != BOOTSTRAP_EXCEPTION_FIELDS:
            self.error(f"{origin}: expected a mapping with temporary and source_cidrs")
            return
        if value.get("temporary") is not True:
            self.error(f"{origin}.temporary: must be true; the exception is temporary")
        sources = value.get("source_cidrs")
        if not isinstance(sources, list) or not sources:
            self.error(f"{origin}.source_cidrs: expected a nonempty list of CIDRs")
            return
        networks = set()
        for index, item in enumerate(sources):
            problem = self.management_cidr_error(item)
            if problem:
                self.error(f"{origin}.source_cidrs[{index}]: {problem}")
            else:
                networks.add(ipaddress.ip_network(item, strict=True))
        allow = values.get("node_port_allow")
        if allow is None or not isinstance(allow[0], list) or not allow[0]:
            return
        try:
            allowed = {ipaddress.ip_network(item, strict=True) for item in allow[0]}
        except (TypeError, ValueError):
            return
        if networks and networks != allowed:
            self.error(f"{origin}.source_cidrs: must equal node_port_allow; the exception is ACL-scoped")

    def management_cidr_error(self, item: Any) -> str | None:
        if not isinstance(item, str) or "/" not in item:
            return "must be a CIDR such as 192.0.2.0/24"
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            return f"invalid CIDR {item!r}"
        if network.is_loopback and str(network) not in ("127.0.0.1/32", "::1/128"):
            return "only exact standard loopback management is allowed"
        if network.is_multicast or network.is_unspecified or network.prefixlen < (8 if network.version == 4 else 32):
            return "unsafe or wide management CIDR"
        if self.example and str(network) not in ("127.0.0.1/32", "::1/128") and not in_networks(network, DOCUMENTATION_NETWORKS + PRIVATE_NETWORKS):
            return "example CIDR must be in documentation or private ranges"
        return None

    def check_node_port_allow(self, value: Any) -> str | None:
        if not isinstance(value, list):
            return "must be a list of CIDRs"
        if not value:
            return "must not be empty"
        seen = set()
        for index, item in enumerate(value):
            problem = self.management_cidr_error(item)
            if problem:
                return f"item {index}: {problem}"
            network = str(ipaddress.ip_network(item, strict=True))
            if network in seen:
                return f"item {index}: duplicate CIDR"
            seen.add(network)
        return None

    def check_reality_sni(self, value: Any) -> str | None:
        if not is_dns_name(value, min_labels=2):
            return "must be a non-empty DNS name"
        if self.example and not value.lower().endswith(EXAMPLE_SNI_SUFFIX):
            return f"example SNI must end with {EXAMPLE_SNI_SUFFIX}"
        return None

    def validate_profiles(self) -> None:
        """Static cross-role gates; DNS/certificate/runtime remain separate."""
        contract = profile_contract()
        nodes = {}
        for group in ("exit", "relay"):
            if len(self.groups[group]) != 1:
                continue
            host = next(iter(self.groups[group]))
            values = {key: item[0] for key, item in self.effective(group, host).items()}
            nodes[group] = values
            try:
                contract.validate_host(values, group)
                contract.validate_probe_url(values.get("profiles_probe_url", ""))
                contract.validate_profile_options(values)
            except contract.Invalid as error:
                self.error(f"host {host}: {error}")
            except (TypeError, ValueError):
                self.error(f"host {host}: invalid self-steal input type")
        if set(nodes) != {"exit", "relay"}:
            return
        exit_host, relay = nodes["exit"], nodes["relay"]
        try:
            contract.validate_addresses(exit_host, relay)
        except contract.Invalid as error:
            self.error(f"profiles: {error}")
        if self.example:
            for version in (4, 6):
                key = f"relay_egress_ipv{version}"
                address = ip_or_none(relay.get(key, "")) if isinstance(relay.get(key), str) else None
                if address is not None and not in_networks(address, DOCUMENTATION_NETWORKS):
                    self.error(f"relay: {key} example egress must be in documentation ranges")
        ports = relay.get("relay_slot_ports")
        if not isinstance(ports, list) or len(ports) != exit_host.get("egress_slots"):
            self.error("relay: relay_slot_ports must contain one port per fixed slot")

    def summary(self) -> str:
        hosts = "; ".join(f"{group}: {', '.join(hosts) or '-'}" for group, hosts in self.groups.items())
        mode = "example" if self.example else "regular"
        return f"Inventory OK: {self.label(self.path)} ({mode}; {hosts})"


def expected_state(inventory: Inventory) -> dict[str, Any]:
    """Managed-state publication contract derived from a valid inventory.

    The expected state is not a second renderer: it contains only the declared
    inventory authority (subscription endpoint, node API exposure, cover
    identity). Role-owned defaults stay in the roles.
    """
    layer = inventory.panel_layer()
    if layer is None:
        raise ValueError("inventory has no single panel host")
    group, panel_host = layer
    values = inventory.effective(group, panel_host)
    subscription_host = values["subscription_public_host"][0]
    subscription_path = values["subscription_public_path"][0]
    state: dict[str, Any] = {
        "schema": STATE_SCHEMA,
        "panel_host": panel_host,
        "subscription": {
            "host": subscription_host,
            "path": subscription_path,
            "server_name": subscription_host,
            "path_prefix": subscription_path,
            "sub_public_domain": subscription_host + subscription_path.rstrip("/"),
        },
        "nodes": {},
    }
    for node_group in NODE_GROUPS:
        node_host = next(iter(inventory.groups[node_group]))
        node_values = inventory.effective(node_group, node_host)
        state["nodes"][node_host] = {
            "api_port": node_values["node_api_port"][0],
            "node_port_allow": sorted(
                str(ipaddress.ip_network(item, strict=True))
                for item in node_values["node_port_allow"][0]
            ),
            "base_firewall_vpn_ports": sorted(
                f"{item['proto']}/{item['port']}"
                for item in node_values["base_firewall_vpn_ports"][0]
            ),
            # Role/contract default for an omitted value, from the shared
            # profile contract; an explicit value is preserved.
            "cover_tls_port": node_values.get(
                "cover_tls_port", (profile_contract().DEFAULT_COVER_TLS_PORT,)
            )[0],
            "reality_sni": node_values["reality_sni"][0],
        }
    return state


def write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_state(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"cannot read snapshot: {exc.strerror}"
    try:
        data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        return None, "snapshot is not valid JSON/YAML"
    if not isinstance(data, dict):
        return None, "snapshot must be a mapping"
    if type(data.get("schema")) is not int or data.get("schema") != STATE_SCHEMA:
        return None, f"snapshot schema must be {STATE_SCHEMA}"
    for section in ("subscription", "nodes"):
        if section in data and not isinstance(data[section], dict):
            return None, f"snapshot section '{section}' must be a mapping"
    if "panel_host" in data and not isinstance(data["panel_host"], str):
        return None, "snapshot panel_host must be a string"
    return data, None


def _scalar_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def state_drift(expected: Any, observed: Any, path: str = "") -> list[str]:
    """Deterministic missing/extra/mismatch paths; values are never included."""
    problems: list[str] = []
    if isinstance(expected, dict):
        if not isinstance(observed, dict):
            return [f"{path or '<root>'}: mismatch"]
        for key in sorted(set(expected) | set(observed), key=str):
            child = f"{path}.{key}" if path else str(key)
            if key not in observed:
                problems.append(f"{child}: missing")
            elif key not in expected:
                problems.append(f"{child}: extra")
            else:
                problems.extend(state_drift(expected[key], observed[key], child))
        return problems
    if isinstance(expected, list):
        if not isinstance(observed, list):
            return [f"{path}: mismatch"]
        if sorted(map(_scalar_key, expected)) != sorted(map(_scalar_key, observed)):
            problems.append(f"{path}: mismatch")
        return problems
    if type(expected) is not type(observed) or expected != observed:
        problems.append(f"{path}: mismatch")
    return problems


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
    parser.add_argument(
        "--state",
        type=Path,
        help="observed managed-state snapshot; report drift and exit 1",
    )
    parser.add_argument(
        "--write-expected",
        type=Path,
        help="write the canonical expected state derived from the inventory",
    )
    args = parser.parse_args(argv)
    inventory = validate(args.inventory)
    if inventory.errors:
        print(f"Inventory invalid: {len(inventory.errors)} error(s)", file=sys.stderr)
        for message in inventory.errors:
            print(f"  - {message}", file=sys.stderr)
        return 1
    print(inventory.summary())
    state = expected_state(inventory)
    if args.write_expected:
        write_state(args.write_expected, state)
        print(f"Expected state written: {args.write_expected}")
    if args.state:
        observed, problem = load_state(args.state)
        if problem:
            print(f"Invalid state snapshot: {problem}", file=sys.stderr)
            return 2
        drift = state_drift(state, observed)
        if drift:
            print(f"State drift: {len(drift)} difference(s)", file=sys.stderr)
            for path in drift:
                print(f"  - {path}", file=sys.stderr)
            return 1
        print(f"State OK: {args.state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

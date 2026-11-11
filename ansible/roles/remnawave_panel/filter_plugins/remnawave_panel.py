"""Filters for the remnawave_panel role.

Error messages and returned problem lists name keys and line numbers only,
never secret values.
"""

import ipaddress
import re

from ansible.errors import AnsibleFilterError

KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
PG_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
# Used verbatim inside DATABASE_URL, so only URL-unreserved characters.
PG_PASSWORD_RE = re.compile(r"^[A-Za-z0-9._~-]{16,}$")
FORBIDDEN_VALUE_CHARS = ("'", "\n", "\r", "\x00")


def parse_env(text):
    """Parse a dotenv file: KEY=VALUE lines, optional `export`, optional quotes."""
    if not isinstance(text, str):
        raise AnsibleFilterError("remnawave_panel: env file content must be text")
    result = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not KEY_RE.match(key):
            raise AnsibleFilterError(
                "remnawave_panel: env file line %d is not KEY=VALUE with an upper-case key" % number
            )
        if key in result:
            raise AnsibleFilterError("remnawave_panel: env file defines %s more than once" % key)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        result[key] = value
    return result


def normalize_env(env):
    """Turn an inventory mapping into str -> str, rejecting nested values."""
    if not isinstance(env, dict):
        raise AnsibleFilterError("remnawave_panel: remnawave_panel_env must be a mapping")
    result = {}
    for key, value in env.items():
        if isinstance(value, (dict, list, tuple, set)) or value is None:
            raise AnsibleFilterError("remnawave_panel: remnawave_panel_env.%s must be a scalar" % key)
        if isinstance(value, bool):
            value = "true" if value else "false"
        result[str(key)] = str(value)
    return result


def env_problems(env, required, managed):
    """Return human-readable problems that mention key names only."""
    problems = []
    for key in sorted(env):
        if not KEY_RE.match(key):
            problems.append("%s: invalid key name" % key)
        if key in managed:
            problems.append("%s: managed by the role, remove it from the secrets" % key)
        value = env[key]
        if any(char in value for char in FORBIDDEN_VALUE_CHARS):
            problems.append("%s: value contains a single quote, newline or NUL" % key)
    for key in required:
        value = env.get(key, "").strip()
        if not value:
            problems.append("%s: required and must be non-empty" % key)
        elif value == "change_me":
            problems.append("%s: placeholder value change_me is not allowed" % key)
    for key in ("POSTGRES_USER", "POSTGRES_DB"):
        if env.get(key) and not PG_NAME_RE.match(env[key]):
            problems.append("%s: must match %s" % (key, PG_NAME_RE.pattern))
    if env.get("POSTGRES_PASSWORD") and not PG_PASSWORD_RE.match(env["POSTGRES_PASSWORD"]):
        problems.append("POSTGRES_PASSWORD: must be at least 16 characters of [A-Za-z0-9._~-]")
    return problems


def is_loopback(value):
    """True only for an IPv4 literal in 127.0.0.0/8 or exactly ::1."""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if address.version == 4:
        return address in ipaddress.ip_network("127.0.0.0/8")
    return address == ipaddress.ip_address("::1")


def compose_violations(config, project, panel_service, panel_bind, panel_port):
    """Check `docker compose config --format json` output against the role policy."""
    problems = []
    if config.get("name") != project:
        problems.append("project name is not %s" % project)
    services = config.get("services") or {}
    if panel_service not in services:
        problems.append("service %s is missing" % panel_service)
    for name, service in sorted(services.items()):
        if service.get("privileged"):
            problems.append("%s: privileged mode" % name)
        for field in ("network_mode", "pid", "ipc", "userns_mode"):
            if service.get(field) == "host":
                problems.append("%s: %s host" % (name, field))
        for volume in service.get("volumes") or []:
            source = str(volume.get("source", ""))
            if source.endswith("docker.sock") or volume.get("type") == "bind":
                problems.append("%s: bind mount %s" % (name, source))
        if service.get("restart") != "unless-stopped":
            problems.append("%s: restart is not unless-stopped" % name)
        if not service.get("healthcheck"):
            problems.append("%s: no healthcheck" % name)
        ports = service.get("ports") or []
        if name != panel_service:
            if ports:
                problems.append("%s: publishes host ports" % name)
            continue
        if len(ports) != 1:
            problems.append("%s: must publish exactly one port" % name)
        for port in ports:
            if str(port.get("host_ip")) != str(panel_bind) or str(port.get("published")) != str(panel_port):
                problems.append("%s: port is not bound to panel_bind:panel_port" % name)
    return problems


class FilterModule:
    def filters(self):
        return {
            "remnawave_panel_parse_env": parse_env,
            "remnawave_panel_normalize_env": normalize_env,
            "remnawave_panel_env_problems": env_problems,
            "remnawave_panel_is_loopback": is_loopback,
            "remnawave_panel_compose_violations": compose_violations,
        }

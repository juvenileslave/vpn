"""Bootstrap-specific checks that reuse the existing role validators.

The role deliberately keeps no second copy of the administrator, CIDR or panel
policy: ``admin_errors``/``cidr_error`` come from the base role's plugin file,
and panel pins/domains/secrets are validated by the panel role's own
``validate.yml`` from the bootstrap playbook. This module only adds the
reconnection, listener and ssh-option checks that no role owns yet.
"""

from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path
import re
import shlex

from ansible.errors import AnsibleFilterError

_BASE_PLUGIN = (
    Path(__file__).resolve().parents[2] / "base" / "filter_plugins" / "vpn_base.py"
)


def _load_base_plugin():
    spec = importlib.util.spec_from_file_location("vpn_base_bootstrap", _BASE_PLUGIN)
    if spec is None or spec.loader is None:
        raise AnsibleFilterError("bootstrap: не найден общий валидатор base")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    _vpn_base = _load_base_plugin()
except (OSError, ImportError) as exc:
    raise AnsibleFilterError("bootstrap: не удалось загрузить валидатор base: %s" % exc)


def admin_errors(users) -> list[str]:
    return _vpn_base.admin_errors(users)


def cidr_error(value):
    return _vpn_base.ssh_cidr_error(value)


def key_matches(derived_line, declared_keys) -> bool:
    """Whether the public line derived from a private key is declared."""
    if not isinstance(derived_line, str):
        return False
    derived = derived_line.split()
    if len(derived) < 2:
        return False
    key_type, body = derived[0], derived[1]
    for key in declared_keys or []:
        if not isinstance(key, str):
            continue
        tokens = key.split()
        if len(tokens) >= 2 and tokens[0] == key_type and tokens[1] == body:
            return True
    return False


def ssh_args(value):
    """Split ``ansible_ssh_common_args`` into argv elements."""
    if value is None or value == "":
        return []
    if not isinstance(value, str):
        raise AnsibleFilterError("ansible_ssh_common_args: ожидается строка")
    try:
        return shlex.split(value)
    except ValueError as exc:
        raise AnsibleFilterError(
            "ansible_ssh_common_args: некорректные кавычки"
        ) from exc


_WEAK_SSH_OPTIONS = {
    # OpenSSH resolves ``off`` and ``false`` to the same disabled check as
    # ``no``; comparing literals would let -o StrictHostKeyChecking=off pass.
    "stricthostkeychecking": (
        ("no", "off", "false", "accept-new"),
        "StrictHostKeyChecking=no/off/accept-new отключает проверку host key",
    ),
    "userknownhostsfile": (
        ("/dev/null", "none"),
        "UserKnownHostsFile=/dev/null|none отключает проверку host key",
    ),
    "globalknownhostsfile": (
        ("/dev/null", "none"),
        "GlobalKnownHostsFile=/dev/null|none отключает проверку host key",
    ),
    "passwordauthentication": (("yes",), "PasswordAuthentication=yes ослабляет key-only доступ"),
    "kbdinteractiveauthentication": (("yes",), "KbdInteractiveAuthentication=yes ослабляет key-only доступ"),
}
_FORBIDDEN_SSH_OPTIONS = {
    "identityfile": "нельзя добавлять второй identity file",
    "user": "пользователь SSH задаётся bootstrap_admin_name",
    "port": "порт SSH задаётся ansible_port",
    "hostname": "хост SSH задаётся inventory ansible_host",
}
_FORBIDDEN_SSH_FLAGS = {
    "i": "нельзя добавлять identity file в ansible_ssh_common_args",
    "F": "нельзя переопределять ssh config в ansible_ssh_common_args",
    "p": "порт SSH задаётся ansible_port",
    "l": "пользователь SSH задаётся bootstrap_admin_name",
}
_PROXY_SSH_OPTIONS = frozenset({"proxyjump", "proxycommand", "proxyusefdpass"})
_SSH_FLAGS_WITH_ARG = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
_OPTION_SPLIT = re.compile(r"^([^\s=]+)(?:(?:\s*=\s*|\s+)(.*))?$", re.DOTALL)


def _option_key_value(option):
    option = option.strip()
    if not option:
        return "", ""
    match = _OPTION_SPLIT.match(option)
    if not match:
        return "", option.lstrip("=").strip().lower()
    key = match.group(1).lower()
    value = (match.group(2) or "").strip().lower()
    return key, value


def _ssh_option_problems(option):
    key, value = _option_key_value(option)
    if key in _FORBIDDEN_SSH_OPTIONS:
        return [_FORBIDDEN_SSH_OPTIONS[key]]
    if key in _WEAK_SSH_OPTIONS:
        weak_values, message = _WEAK_SSH_OPTIONS[key]
        if any(value == weak for weak in weak_values):
            return [message]
    if key == "preferredauthentications" and "password" in value:
        return ["PreferredAuthentications добавляет пароль"]
    return []


def direct_ssh_args(value) -> list[str]:
    """Strip ProxyJump/ProxyCommand/-J options for direct break-glass probes.

    Preserves host-key checking, known_hosts, timeouts, identity and other
    explicit SSH options. Fails closed if proxy options cannot be stripped
    unambiguously.
    """
    args = ssh_args(value)
    result: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            raise AnsibleFilterError(
                "ansible_ssh_common_args: разделитель '--' недопустим для прямого пути"
            )
        if not token.startswith("-") or token == "-":
            raise AnsibleFilterError(
                "ansible_ssh_common_args: позиционный аргумент недопустим"
            )
        if token.startswith("--"):
            raise AnsibleFilterError(
                "ansible_ssh_common_args: неизвестный длинный флаг недопустим для прямого пути"
            )
        if token == "-o":
            if (index + 1 >= len(args) or not args[index + 1].strip()
                    or args[index + 1].startswith("-")):
                raise AnsibleFilterError(
                    "ansible_ssh_common_args: -o без значения"
                )
            key, _opt_val = _option_key_value(args[index + 1])
            if not key:
                raise AnsibleFilterError(
                    "ansible_ssh_common_args: пустое имя опции -o"
                )
            if key not in _PROXY_SSH_OPTIONS:
                result.extend((token, args[index + 1]))
            index += 2
            continue
        if token.startswith("-o") and len(token) > 2:
            option = token[2:]
            if not option.strip():
                raise AnsibleFilterError(
                    "ansible_ssh_common_args: пустая опция -o"
                )
            key, _opt_val = _option_key_value(option)
            if not key:
                raise AnsibleFilterError(
                    "ansible_ssh_common_args: пустое имя опции -o"
                )
            if key not in _PROXY_SSH_OPTIONS:
                result.append(token)
            index += 1
            continue
        if token == "-J":
            if (index + 1 >= len(args) or not args[index + 1].strip()
                    or args[index + 1].startswith("-")):
                raise AnsibleFilterError(
                    "ansible_ssh_common_args: -J без значения"
                )
            index += 2
            continue
        if token.startswith("-J") and len(token) > 2:
            index += 1
            continue
        arg_flag = None
        for pos, flag in enumerate(token[1:], start=1):
            if flag in ("J", "o"):
                raise AnsibleFilterError(
                    "ansible_ssh_common_args: комбинированный флаг с -J/-o нельзя безопасно разобрать для прямого пути"
                )
            if flag in _SSH_FLAGS_WITH_ARG:
                arg_flag = (pos, flag)
                break
        if arg_flag is not None and arg_flag[0] == len(token) - 1:
            if index + 1 >= len(args) or not args[index + 1].strip():
                raise AnsibleFilterError(
                    f"ansible_ssh_common_args: -{arg_flag[1]} без значения"
                )
            result.extend((token, args[index + 1]))
            index += 2
            continue
        result.append(token)
        index += 1
    return result


def ssh_args_problems(value) -> list[str]:
    """Refuse inventory SSH options that would weaken the bootstrap probe."""
    if value is None or value == "":
        return []
    if not isinstance(value, str):
        return ["ansible_ssh_common_args: ожидается строка"]
    try:
        args = shlex.split(value)
    except ValueError:
        return ["ansible_ssh_common_args: некорректные кавычки"]

    problems = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-o":
            if index + 1 < len(args):
                problems.extend(_ssh_option_problems(args[index + 1]))
                index += 2
            else:
                problems.append("ansible_ssh_common_args: -o без значения")
                index += 1
            continue
        if token.startswith("-o") and len(token) > 2:
            problems.extend(_ssh_option_problems(token[2:]))
            index += 1
            continue
        if token.startswith("-") and len(token) > 1 and not token.startswith("--"):
            for pos, flag in enumerate(token[1:], start=1):
                if flag in _FORBIDDEN_SSH_FLAGS:
                    problems.append(_FORBIDDEN_SSH_FLAGS[flag])
                    if pos == len(token) - 1:
                        index += 1
                    break
                if flag in _SSH_FLAGS_WITH_ARG:
                    if pos == len(token) - 1:
                        index += 1
                    break
        index += 1
    try:
        direct_ssh_args(value)
    except AnsibleFilterError as exc:
        problems.append(str(exc))
    # Keep the message order stable and avoid duplicate lines.
    return list(dict.fromkeys(problems))


def _normalize_address(host):
    """Return an ``ipaddress`` object for a listening address, or None."""
    host = str(host).strip()
    if host in ("", "*"):
        return None
    host = host.strip("[]").split("%", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _tcp_listeners(ss_output):
    listeners = []
    for line in (ss_output or "").splitlines():
        fields = line.split()
        # ``ss -t`` omits the Netid column; it appears only when several
        # protocols are selected. Accept both layouts and take the local
        # address from the penultimate column.
        if fields[:1] == ["tcp"]:
            fields = fields[1:]
        if len(fields) < 4 or fields[0] != "LISTEN":
            continue
        host, _, port = fields[-2].rpartition(":")
        if not port.isdigit():
            continue
        listeners.append((host, int(port)))
    return listeners


def listener_problems(ss_output, bind, panel_port, forbidden_ports=None) -> list[str]:
    """Problems that mean the panel stack is published beyond its loopback port."""
    try:
        bind_address = ipaddress.ip_address(str(bind))
        panel_port = int(panel_port)
    except (TypeError, ValueError):
        return ["panel_bind/panel_port не являются корректным адресом и портом"]

    listeners = _tcp_listeners(ss_output)
    problems = []
    panel = [(host, port) for host, port in listeners if port == panel_port]
    if not panel:
        problems.append(
            "%s:%s не слушает (в --check новая панель не запускается; это не PASS)"
            % (bind_address, panel_port)
        )
    for host, port in panel:
        if _normalize_address(host) != bind_address:
            problems.append(
                "порт панели опубликован не только на %s: %s:%s"
                % (bind_address, host, port)
            )
    for forbidden in forbidden_ports or []:
        published = sorted({host for host, port in listeners if port == int(forbidden)})
        if published:
            problems.append(
                "порт %s опубликован на хосте: %s" % (forbidden, ", ".join(published))
            )
    return problems


def panel_url(bind, port) -> str:
    address = ipaddress.ip_address(str(bind))
    host = "[%s]" % address if address.version == 6 else str(address)
    return "http://%s:%s/" % (host, int(port))


class FilterModule:
    def filters(self):
        return {
            "bootstrap_admin_errors": admin_errors,
            "bootstrap_cidr_error": cidr_error,
            "bootstrap_key_matches": key_matches,
            "bootstrap_ssh_args": ssh_args,
            "bootstrap_direct_ssh_args": direct_ssh_args,
            "bootstrap_ssh_args_problems": ssh_args_problems,
            "bootstrap_listener_problems": listener_problems,
            "bootstrap_panel_url": panel_url,
        }

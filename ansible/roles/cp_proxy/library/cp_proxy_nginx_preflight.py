#!/usr/bin/python
"""Read-only preflight for the cp_proxy role.

Parses the effective nginx configuration (`nginx -T`), ignores the files owned
by the role and reports server_name/listen conflicts with other vhosts. It also
refuses to take over an existing site file that lacks the ownership marker.
Nothing on the host is modified.
"""

from __future__ import annotations

import os
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: cp_proxy_nginx_preflight
short_description: Detect nginx vhost conflicts before cp_proxy writes its site file
options:
  server_name: {type: str, required: true}
  owned_paths: {type: list, elements: str, required: true}
  marker: {type: str, required: true}
  http_port: {type: int, default: 80}
  https_port: {type: int, default: 443}
"""

FILE_HEADER = re.compile(r"^# configuration file (.+):$")


def split_files(dump: str) -> list[tuple[str, str]]:
    """Split `nginx -T` output into (path, text) segments."""
    files: list[tuple[str, list[str]]] = []
    for line in dump.splitlines():
        match = FILE_HEADER.match(line)
        if match:
            files.append((match.group(1), []))
        elif files:
            files[-1][1].append(line)
    return [(path, "\n".join(lines)) for path, lines in files]


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif ch in "{};":
            tokens.append(ch)
            i += 1
        elif ch in "\"'":
            j = i + 1
            buf = []
            while j < n and text[j] != ch:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(text[j])
                j += 1
            tokens.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                # `${var}` must not be split on its braces.
                if text[j] == "$" and j + 1 < n and text[j + 1] == "{":
                    end = text.find("}", j)
                    j = end + 1 if end != -1 else n
                    continue
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def parse(tokens: list[str]) -> list[dict]:
    """Build a tree of directives: {name, args, block}."""
    root: list[dict] = []
    stack = [root]
    current: list[str] = []
    for tok in tokens:
        if tok == ";":
            if current:
                stack[-1].append({"name": current[0], "args": current[1:], "block": None})
            current = []
        elif tok == "{":
            node = {"name": current[0] if current else "", "args": current[1:], "block": []}
            stack[-1].append(node)
            stack.append(node["block"])
            current = []
        elif tok == "}":
            if len(stack) > 1:
                stack.pop()
            current = []
        else:
            current.append(tok)
    return root


def find_servers(nodes: list[dict], context: str, out: list[tuple[str, dict]]) -> None:
    for node in nodes:
        if node["block"] is None or node["name"] in ("upstream", "map", "types", "location"):
            continue
        if node["name"] == "server":
            # Top-level servers come from files included inside `http {}`
            # (sites-enabled, conf.d), which nginx -T prints as own segments.
            out.append(("http" if context == "main" else context, node))
            continue
        child = node["name"] if node["name"] in ("http", "stream") else context
        find_servers(node["block"], child, out)


def listen_port(address: str) -> int | None:
    if address.startswith("unix:"):
        return None
    if address.startswith("["):
        _, _, rest = address.partition("]")
        return int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 80
    if address.isdigit():
        return int(address)
    host, sep, port = address.rpartition(":")
    if sep and port.isdigit():
        return int(port)
    return 80


def name_matches(pattern: str, name: str) -> bool:
    pattern = pattern.lower()
    if pattern.startswith("~"):
        try:
            return re.search(pattern[1:], name, re.IGNORECASE) is not None
        except re.error:
            return True  # Unknown regex syntax: be conservative.
    if pattern.startswith("."):
        return name == pattern[1:] or name.endswith(pattern)
    if pattern.startswith("*."):
        return name.endswith(pattern[1:])
    if pattern.endswith(".*"):
        return name.startswith(pattern[:-1])
    return pattern == name


def main() -> None:
    module = AnsibleModule(
        argument_spec=dict(
            server_name=dict(type="str", required=True),
            owned_paths=dict(type="list", elements="str", required=True),
            marker=dict(type="str", required=True),
            http_port=dict(type="int", default=80),
            https_port=dict(type="int", default=443),
        ),
        supports_check_mode=True,
    )
    p = module.params
    name = p["server_name"].lower()
    owned = {os.path.realpath(path) for path in p["owned_paths"]} | set(p["owned_paths"])

    for path in p["owned_paths"]:
        if os.path.lexists(path) and not os.path.islink(path):
            with open(path, encoding="utf-8", errors="replace") as handle:
                if p["marker"] not in handle.read():
                    module.fail_json(
                        msg=f"{path} exists but is not managed by cp_proxy (marker missing); refusing to overwrite it"
                    )

    nginx = module.get_bin_path("nginx", required=True)
    rc, out, err = module.run_command([nginx, "-T"])
    if rc != 0:
        module.fail_json(msg="current nginx configuration is invalid; fix it before applying cp_proxy", stderr=err)

    conflicts: list[str] = []
    servers_seen = 0
    for path, text in split_files(out):
        if path in owned or os.path.realpath(path) in owned:
            continue
        servers: list[tuple[str, dict]] = []
        find_servers(parse(tokenize(text)), "main", servers)
        for context, server in servers:
            servers_seen += 1
            directives = [d for d in server["block"] if d["block"] is None]
            names = [arg for d in directives if d["name"] == "server_name" for arg in d["args"]]
            listens = [d["args"] for d in directives if d["name"] == "listen"]
            if context == "http" and not listens:
                listens = [["80"]]
            for args in listens:
                if not args:
                    continue
                port = listen_port(args[0])
                params = set(args[1:])
                where = f"{path}: listen {' '.join(args)}"
                if port not in (p["http_port"], p["https_port"]):
                    continue
                if context == "stream":
                    conflicts.append(f"{where} (stream server binds a port used by cp_proxy)")
                elif "proxy_protocol" in params:
                    conflicts.append(f"{where} (proxy_protocol would apply to cp_proxy traffic)")
                elif port == p["https_port"] and "ssl" not in params:
                    conflicts.append(f"{where} (plain HTTP on the TLS port)")
                elif port == p["http_port"] and "ssl" in params:
                    conflicts.append(f"{where} (TLS on the HTTP port)")
                elif context == "http" and any(name_matches(n, name) for n in names):
                    conflicts.append(f"{path}: server_name {' '.join(names)} already serves {name} on port {port}")

    if conflicts:
        module.fail_json(msg="nginx conflicts detected; cp_proxy will not overwrite them", conflicts=sorted(set(conflicts)))
    module.exit_json(changed=False, servers_checked=servers_seen)


if __name__ == "__main__":
    main()

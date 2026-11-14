"""Synthetic public topology and freshly generated disposable credentials."""
import base64
import importlib.util
from pathlib import Path
import secrets
import uuid
import yaml

ROOT = Path(__file__).resolve().parents[4]
MODULE = ROOT / "ansible/roles/profiles/module_utils/profile_bundle.py"
spec = importlib.util.spec_from_file_location("bundle", MODULE)
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def inputs(users=2):
    example = ROOT / "ansible/inventories/example"
    common = yaml.safe_load((example / "group_vars/all.yml").read_text())
    topology = {key: common[key] for key in ("egress_slots", "egress_family", "s2s_family", "slot_fanout", "xhttp_path", "xhttp_mode", "profiles_probe_url")}
    host_defaults = {key: value for key, value in common.items() if key not in topology}
    for kind in ("exit", "relay"):
        topology[kind] = {**host_defaults, **yaml.safe_load((example / ("host_vars/" + kind + "-example.yml")).read_text())}
    credential = {}
    for kind in ("exit", "relay"):
        private = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        credential[kind] = {"private_key": private, "public_key": bundle.public_key(private), "short_ids": [secrets.token_hex(8)]}
    secret = {"profiles_credentials": credential, "exit_direct_client_ids": [str(uuid.uuid4()) for _ in range(users)], "transit_client_ids": [str(uuid.uuid4()) for _ in range(topology["egress_slots"])], "relay_client_ids": [str(uuid.uuid4()) for _ in range(users)], "profiles_user_slots": [0] * users, "profiles_upstreams": {}, "profiles_revoked_client_ids": []}
    return topology, secret


def secret_strings(value):
    if isinstance(value, dict):
        return [s for v in value.values() for s in secret_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in secret_strings(v)]
    return [value] if isinstance(value, str) and len(value) >= 16 else []

#!/usr/bin/env python3
"""Issue #55: actual vpnctl/Xray paths on the accepted, fresh #47 guest only."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import stat
import subprocess
import time
import uuid

from runtime_vm import ROOT, command, guard_identity, private_json
from fixtures import secret_strings

PATTERN = bytes(range(256)) * 256
AUTH_BYTES = 256
SMALL_BYTES = 1 << 20
LARGE_BYTES = 20 << 20


def payload_digest(size):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        part = PATTERN[:min(len(PATTERN), remaining)]
        digest.update(part)
        remaining -= len(part)
    return digest.hexdigest()


def serve_http(handler, logfile, lock):
    """Only payload behavior is synthetic; VLESS/REALITY is the real stock core."""
    modes = {"auth": AUTH_BYTES, "small": SMALL_BYTES, "large": LARGE_BYTES,
             "truncated": LARGE_BYTES, "slow": LARGE_BYTES, "hold": LARGE_BYTES,
             "cancel": LARGE_BYTES, "short": 64, "corrupt": SMALL_BYTES}
    label = handler.path.removeprefix("/ladder/")
    if label not in modes:
        handler.send_response(404)
        handler.end_headers()
        return
    size = modes[label]
    flow = secrets.token_hex(8)

    def receipt(phase, **facts):
        with lock:
            with open(logfile, "a") as output:
                output.write(json.dumps({"operation": "ladder-http", "phase": phase,
                    "label": label, "flow_id": flow, "source": handler.client_address[0], **facts}) + "\n")

    receipt("started", representation_bytes=size)
    handler.send_response(200)
    handler.send_header("Content-Length", str(size))
    handler.send_header("Content-Type", "application/octet-stream")
    handler.end_headers()
    sent, digest, start = 0, hashlib.sha256(), time.monotonic()
    limit = 17 << 10 if label in ("truncated", "hold", "cancel") else size
    try:
        while sent < limit:
            part = PATTERN[:min(len(PATTERN), limit-sent)]
            if label == "corrupt":
                part = bytes(value ^ 1 for value in part)
            handler.wfile.write(part)
            handler.wfile.flush()
            digest.update(part)
            sent += len(part)
            if label == "slow":
                time.sleep(len(part)/(2 << 20))
        if label in ("hold", "cancel"):
            time.sleep(10)
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        handler.close_connection = True
        receipt("finished", bytes_sent=sent, body_sha256=digest.hexdigest(),
                seconds=time.monotonic()-start, complete=sent == size)


class LadderAcceptance:
    def __init__(self, lab, candidate):
        guard_identity()
        self.lab, self.candidate = lab, candidate
        self.work = lab.work / "ladder"
        self.work.mkdir(mode=0o700)
        self.temporary = self.work / "temporary"
        self.temporary.mkdir(mode=0o700)
        self.database = self.work / "state.db"
        self.binary = self.work / "vpnctl"
        self.inputs = self.work / "inputs.json"
        self.logs = lab.work / "sink-sources.private.jsonl"
        self.canaries = list(secret_strings(lab.secret))
        self.table = lab.prefix + "_probe"
        self.table_exists = False
        self.reports = {}
        self.lab.evidence["scenarios"]["probe_ladder"] = self.reports
        self.lab.evidence["probe_store_reader"] = {"sqlite_version": sqlite3.sqlite_version}
        self.env = {**lab.core_env, "TMPDIR": str(self.temporary), "GOTOOLCHAIN": "auto", "GOWORK": "off"}
        self.vantages = [{"name": "synthetic-inside", "network": "synthetic-client-netns", "kind": "in_country"},
                         {"name": "synthetic-outside", "network": "synthetic-outsider-netns", "kind": "outside"}]
        self.budgets = {"overall": "90s", "setup": "5s", "tcp": "2s", "tls": "3s",
                        "auth": "12s", "small": "10s", "large": "30s", "control": "3s"}

    def build(self):
        self.lab.stage = "probe-ladder-actual-binary-build"
        result = subprocess.run(["go", "build", "-mod=readonly", "-o", str(self.binary), "./cmd/vpnctl"],
            cwd=ROOT / "vpnctl", env=self.env, capture_output=True, timeout=900, check=False)
        if result.returncode:
            self.lab.evidence["public_build_exit"] = result.returncode
            raise AssertionError("vpnctl disposable build failed; private diagnostics withheld")
        inodes = [Path("/run/netns/" + self.lab.ns(kind)).stat().st_ino for kind in ("client", "outsider")]
        if inodes[0] == inodes[1]:
            raise AssertionError("probe vantages share a network namespace")
        self.lab.evidence["probe_vantage_scope"] = {
            "distinct_actual_namespaces": True, "geography": "synthetic only, not actual country/provider evidence",
            "client_to_node_family_only": True, "relay_same_exit_s2s_policy_unchanged": True}

    def endpoint(self, label, size):
        return {"address": "192.0.2.100", "port": 18081, "url": "http://192.0.2.100:18081/ladder/" + label,
                "bytes": size, "sha256": payload_digest(size)}

    def node(self, label, *, kind="direct", large="large", small="small", profile=None, sni=None):
        host = self.lab.topology["exit" if kind == "direct" else "relay"]
        return {"name": label, "ipv4": host["public_ipv4"], "ipv6": host["public_ipv6"],
            "port": host["exit_direct_port"] if kind == "direct" else host["relay_slot_ports"][0],
            "server_name": sni or host["reality_sni"], "roots_file": str(self.lab.trust),
            "profile_file": str(profile or (self.candidate / "clients" / (kind + "-0.json"))),
            "endpoints": {"auth": self.endpoint("auth", AUTH_BYTES),
                          "small": self.endpoint(small, SMALL_BYTES), "large": self.endpoint(large, LARGE_BYTES)}}

    def write_inputs(self, node, *, floor=1, budgets=None):
        private_json(self.inputs, {"schema": 1, "local_vantage": self.vantages[0]["name"],
            "vantages": self.vantages, "nodes": [node], "budgets": budgets or self.budgets,
            "throughput_floor_bytes_s": floor, "evidence_window": "10m"})

    def rows(self, *, label=None, phase=None):
        if not self.logs.exists():
            return []
        return [value for line in self.logs.read_text().splitlines()
                if (value := json.loads(line)).get("operation") == "ladder-http"
                and (label is None or value["label"] == label) and (phase is None or value["phase"] == phase)]

    def safe(self, data):
        for value in self.canaries:
            if value.encode() in data:
                raise AssertionError("probe credentials leaked to output or SQLite")

    def check_clean(self):
        if list(self.temporary.iterdir()):
            raise AssertionError("private Xray temporary config remained after probe")
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = Path(str(self.database) + suffix)
            if path.exists():
                self.safe(path.read_bytes())
                if path.stat().st_mode & 0o077:
                    raise AssertionError("probe store or sidecar has group/other access")

    def arguments(self, node, vantage, family, *, diagnose=False, text=False):
        command_args = [str(self.binary), *( ["diagnose"] if diagnose else ["probe", "ladder"] ),
            "--node", node["name"], "--family", family, "--vantage", self.vantages[vantage]["name"],
            "--inputs", str(self.inputs), "--store", str(self.database), "--format", "text" if text else "json"]
        if not diagnose:
            command_args += ["--xray", str(self.lab.xray)]
        return ["ip", "netns", "exec", self.lab.ns("client" if vantage == 0 else "outsider"), *command_args]

    def inspect_pending(self, process):
        deadline = time.monotonic()+15
        observed = False
        descendants = []
        while time.monotonic() < deadline and process.poll() is None:
            directories = list(self.temporary.iterdir())
            if directories:
                for directory in directories:
                    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
                        raise AssertionError("private Xray directory is not 0700")
                    for path in directory.iterdir():
                        if stat.S_IMODE(path.stat().st_mode) != 0o600:
                            raise AssertionError("private Xray config is not 0600")
                argv = Path(f"/proc/{process.pid}/cmdline").read_bytes()
                self.safe(argv)
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
                if not children:
                    time.sleep(.02)
                    continue
                for child in children:
                    self.safe(Path(f"/proc/{child}/cmdline").read_bytes())
                descendants = children
                observed = True
                break
            time.sleep(.02)
        if not observed:
            raise AssertionError("actual private Xray process/config was not observed")
        return descendants

    def run_probe(self, node, *, vantage=0, family="ipv4", expected=0, text=False, cancel=False):
        self.lab.stage = "probe-ladder-" + node["name"]
        before = len(self.rows(phase="started"))
        args = self.arguments(node, vantage, family, text=text)
        if cancel:
            pending_count = len(self.rows(label="cancel", phase="started"))
            process = subprocess.Popen(args, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                descendants = self.inspect_pending(process)
                until = time.monotonic()+20
                while len(self.rows(label="cancel", phase="started")) == pending_count:
                    if process.poll() is not None or time.monotonic() > until:
                        raise AssertionError("cancel scenario never reached an authenticated large stream")
                    time.sleep(.02)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
                for child in descendants:
                    if Path("/proc/"+child).exists():
                        raise AssertionError("owned Xray survived CLI cancellation")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            result_code = process.returncode
        else:
            result = subprocess.run(args, env=self.env, capture_output=True, timeout=120, check=False)
            stdout, stderr, result_code = result.stdout, result.stderr, result.returncode
        self.safe(stdout+stderr)
        self.check_clean()
        if result_code != expected:
            self.lab.evidence["public_probe_failure"] = {"scenario": node["name"], "exit_code": result_code}
            raise AssertionError("actual probe CLI exit differs from expected")
        if text:
            if b"throughput: success" not in stdout or b"diagnosis: unknown" not in stdout:
                raise AssertionError("actual text CLI omitted measured stages or conservative verdict")
            self.reports[node["name"]+"-text"] = {"actual_exit": result_code, "text_surface_verified": True}
            return None
        output = json.loads(stdout)
        report = output["probe"]
        if not report["persisted"] or len(report["events"]) != 5 or report["family"] != family:
            raise AssertionError("actual probe report is unpersisted, incomplete or changed family")
        if output["diagnosis"]["scope"]["global"]:
            raise AssertionError("probe CLI made a global claim")
        self.reports[node["name"]+"-"+str(vantage)+"-"+family] = output
        try:
            with sqlite3.connect(self.database) as database:
                rows = database.execute("SELECT stage, family, outcome, error_code, bytes, duration_ns, vantage, network, scope, expected_bytes, body_duration_ns FROM probes WHERE run_id=? ORDER BY id", (report["run_id"],)).fetchall()
        except sqlite3.Error as error:
            self.lab.evidence["probe_store_reader_error"] = {
                "sqlite_version": sqlite3.sqlite_version,
                "code": getattr(error, "sqlite_errorcode", None),
                "name": getattr(error, "sqlite_errorname", None),
            }
            raise AssertionError("native SQLite could not read generated probe observations") from None
        if len(rows) != 5:
            raise AssertionError("probe SQLite does not contain each executed/skipped stage")
        for event, row in zip(report["events"], rows):
            expected_outcome = "success" if event["outcome"] == "success" else "timeout" if event["outcome"] == "timeout" else "failure"
            if row != (event["stage"], family, expected_outcome, event["error_code"], event["bytes"], event["duration_ns"],
                report["vantage"]["name"], report["vantage"]["network"], event["scope"], event["expected_bytes"], event["body_duration_ns"]):
                raise AssertionError("persisted probe facts differ from actual measurements")
        if expected == 0:
            if report["outcome"] != "success" or any(event["outcome"] != "success" for event in report["events"]):
                raise AssertionError("successful CLI did not traverse every authenticated stage")
            for event, count in zip(report["events"][2:], (AUTH_BYTES, SMALL_BYTES, LARGE_BYTES)):
                if event["bytes"] != count or not event["integrity_verified"] or event["body_duration_ns"] <= 0:
                    raise AssertionError("authorized byte/integrity/throughput measurement is missing")
            cert = report["events"][1]["certificate"]
            if not cert["verified"] or not cert["san_match"] or len(cert["issuer_sha256"]) != 64:
                raise AssertionError("cover certificate was not observed and verified")
            started_receipts = self.rows(phase="started")[before:]
            if len(started_receipts) != 3:
                raise AssertionError("probe did not execute exactly one request per authenticated stage")
            flows = {receipt["flow_id"] for receipt in started_receipts}
            until = time.monotonic()+2
            receipts = [receipt for receipt in self.rows(phase="finished") if receipt["flow_id"] in flows]
            while len(receipts) < 3 and time.monotonic() < until:
                time.sleep(.02)
                receipts = [receipt for receipt in self.rows(phase="finished") if receipt["flow_id"] in flows]
            if len(receipts) != 3 or [row["bytes_sent"] for row in receipts] != [AUTH_BYTES, SMALL_BYTES, LARGE_BYTES]:
                raise AssertionError("executed HTTP payload counts differ from reported transfers")
            if any(row["source"] != "192.0.2.10" for row in receipts):
                raise AssertionError("application escaped the accepted exit path")
            if [row["body_sha256"] for row in receipts] != [payload_digest(size) for size in (AUTH_BYTES, SMALL_BYTES, LARGE_BYTES)]:
                raise AssertionError("actual HTTP representation integrity receipt differs")
        return report

    def diagnose(self, node, expected):
        result = subprocess.run(self.arguments(node, 0, "ipv4", diagnose=True), env=self.env, capture_output=True, timeout=10, check=False)
        self.safe(result.stdout+result.stderr)
        self.check_clean()
        output = json.loads(result.stdout)
        verdict = output["diagnosis"]
        if verdict["verdict"] != expected or result.returncode != (3 if expected == "unknown" else 0) or verdict["scope"]["global"]:
            raise AssertionError("actual diagnose verdict/exit/scope differs from conservative contract")
        if verdict["missing_evidence"] is None or (expected == "unknown" and not verdict["missing_evidence"]):
            raise AssertionError("diagnosis omitted missing evidence")
        self.reports[node["name"]+"-diagnosis-"+expected] = output
        return verdict

    def fault(self, rule):
        if self.table_exists:
            command(["nft", "delete", "table", "inet", self.table])
        self.table_exists = True
        command(["nft", "add", "table", "inet", self.table])
        command(["nft", "add", "chain", "inet", self.table, "input", "{ type filter hook input priority -10; policy accept; }"])
        command(["nft", "add", "rule", "inet", self.table, "input", *rule])

    def clear_fault(self):
        if self.table_exists:
            tables = json.loads(command(["nft", "-j", "list", "tables"]))["nftables"]
            if any(value.get("table", {}).get("name") == self.table for value in tables):
                command(["nft", "delete", "table", "inet", self.table])
            tables = json.loads(command(["nft", "-j", "list", "tables"]))["nftables"]
            if any(value.get("table", {}).get("name") == self.table for value in tables):
                raise AssertionError("owned probe fault table remains after cleanup")
            self.table_exists = False

    def execute(self):
        self.build()
        baseline = self.node("relay-baseline", kind="relay")
        self.write_inputs(baseline)
        self.run_probe(baseline)
        self.diagnose(baseline, "unknown")
        self.run_probe(baseline, vantage=1)
        self.run_probe(baseline, family="ipv6")
        direct = self.node("text-surface")
        self.write_inputs(direct)
        self.run_probe(direct, text=True)
        self.diagnose(direct, "unknown")

        for label in ("wrong-key", "wrong-shortid", "wrong-uuid", "wrong-sni"):
            profile = json.loads((self.candidate / "clients/relay-0.json").read_text())
            settings = profile["outbounds"][0]["streamSettings"]["realitySettings"]
            sni = None
            if label == "wrong-key":
                settings["password"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
                self.canaries.append(settings["password"])
            elif label == "wrong-shortid":
                settings["shortId"] = secrets.token_hex(8)
                self.canaries.append(settings["shortId"])
            elif label == "wrong-uuid":
                profile["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = str(uuid.uuid4())
                self.canaries.append(profile["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"])
            else:
                sni = settings["serverName"] = "unknown.example.test"
            file = self.work / (label+".json")
            private_json(file, profile)
            node = self.node(label, kind="relay", profile=file, sni=sni)
            self.write_inputs(node)
            count = len(self.rows(phase="started"))
            report = self.run_probe(node, expected=4)
            first_failure = next(event for event in report["events"] if event["outcome"] != "success")
            if first_failure["stage"] != ("tls" if label == "wrong-sni" else "auth") or len(self.rows(phase="started")) != count:
                raise AssertionError("wrong credentials failed at wrong stage or acquired proxy access")
            self.diagnose(node, "unknown")

        for label, small, code in (("short-body", "short", "size_mismatch"), ("corrupt-body", "corrupt", "integrity_mismatch")):
            node = self.node(label, small=small)
            self.write_inputs(node)
            report = self.run_probe(node, expected=4)
            if report["events"][3]["error_code"] != code or report["events"][4]["outcome"] != "skipped":
                raise AssertionError("bounded size/integrity failure turned into throughput success")

        node = self.node("stream-boundary", large="truncated")
        self.write_inputs(node)
        for vantage in (0, 1):
            report = self.run_probe(node, vantage=vantage, expected=4)
            event = report["events"][4]
            if event["bytes"] != 17 << 10 or event["outcome"] != "early_eof":
                raise AssertionError("actual authenticated interruption lacks 17 KiB measurement")
        self.diagnose(node, "dpi_stream_stall")

        node = self.node("slow-stream", large="slow")
        self.write_inputs(node, floor=4 << 20)
        for vantage in (0, 1):
            report = self.run_probe(node, vantage=vantage)
            event = report["events"][4]
            if LARGE_BYTES/(event["body_duration_ns"]/1e9) >= 4 << 20:
                raise AssertionError("slow stream did not produce a measured low rate")
        self.diagnose(node, "throttling")

        for label in ("deadline", "cancel"):
            node = self.node(label, large="hold" if label == "deadline" else "cancel")
            budgets = {**self.budgets, "large": "2s" if label == "deadline" else "30s"}
            self.write_inputs(node, budgets=budgets)
            report = self.run_probe(node, expected=4, cancel=label == "cancel")
            if report["events"][4]["outcome"] != ("timeout" if label == "deadline" else "canceled"):
                raise AssertionError("overall/stage deadline or SIGTERM did not interrupt authenticated stream")
            self.diagnose(node, "unknown")

        node = self.node("family-isolation")
        self.write_inputs(node)
        self.run_probe(node)
        self.run_probe(node, vantage=1)
        self.fault(["ip6", "daddr", "2001:db8:47::10", "tcp", "dport", "18443", "drop"])
        report = self.run_probe(node, family="ipv6", expected=4)
        if report["events"][0]["outcome"] != "timeout" or any(event["family"] != "ipv6" for event in report["events"]):
            raise AssertionError("closed exit IPv6 implicitly fell back or failed at wrong stage")
        self.run_probe(node)
        self.clear_fault()

        node = self.node("ip-control")
        self.write_inputs(node)
        self.fault(["ip", "saddr", "192.0.2.30", "ip", "daddr", "192.0.2.10", "tcp", "dport", "18443", "drop"])
        self.run_probe(node, expected=4)
        self.diagnose(node, "unknown")
        self.run_probe(node, vantage=1)
        self.diagnose(node, "ip_block")
        self.clear_fault()

        node = self.node("exit-outage")
        self.write_inputs(node)
        command(["docker", "stop", "vpn-remnanode"])
        if json.loads(command(["docker", "inspect", "vpn-remnanode"]))[0]["State"]["Running"]:
            raise AssertionError("exit outage was not an actual stopped Node")
        self.run_probe(node, expected=4)
        self.diagnose(node, "unknown")
        self.run_probe(node, vantage=1, expected=4)
        self.diagnose(node, "node_outage")
        self.check_clean()
        self.lab.evidence["scenarios"]["probe_ladder"] = self.reports
        self.lab.evidence["probe_ladder_acceptance"] = {
            "actual_vpnctl_binary": True, "real_pinned_xray": True, "authenticated_transport": "REALITY/VLESS/XHTTP",
            "immutable_renderer_clients_consumed": True, "payload_counts_and_integrity_receipts_verified": True,
            "observations_round_trip_SQLite": True, "private_modes_observed": "0700/0600",
            "credentials_absent_from_argv_output_SQLite": True, "no_family_fallback": True,
            "specific_censorship_system_detected": False, "automatic_actions": False}


def run_ladder_acceptance(lab, candidate):
    guard_identity()
    acceptance = LadderAcceptance(lab, candidate)
    try:
        acceptance.execute()
    finally:
        failures = []
        for operation in (acceptance.clear_fault, acceptance.check_clean):
            try:
                operation()
            except Exception as error:
                failures.append({"stage": operation.__name__, "type": type(error).__name__})
        if failures:
            lab.evidence["probe_ladder_cleanup_failures"] = failures
            raise AssertionError("owned probe resources did not clean up")

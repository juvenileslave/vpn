#!/usr/bin/env python3
"""Idempotent TLS material for the loopback panel endpoint.

Creates a private CA once and a short-lived leaf certificate for the loopback
name, re-issuing the leaf when it is missing, mismatched or inside the renewal
window. Nothing is signed by a public CA: the CA certificate is the single file
an operator imports into a client trust store. Key material is never printed.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

OPENSSL = "openssl"
ENDDATE_RE = re.compile(r"^notAfter=(?P<value>.+)$", re.MULTILINE)


def parse_enddate(text: str) -> datetime.datetime:
    match = ENDDATE_RE.search(text)
    if not match:
        raise ValueError("openssl output has no notAfter field")
    return datetime.datetime.strptime(match.group("value").strip(), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc
    )


def needs_renewal(expires_at: datetime.datetime, now: datetime.datetime, renew_before_days: int) -> bool:
    return expires_at - now <= datetime.timedelta(days=renew_before_days)


def san_matches(text: str, addresses: list[str], names: list[str]) -> bool:
    expected = {f"IP Address:{address}" for address in addresses} | {f"DNS:{name}" for name in names}
    present = {item.strip() for item in re.split(r",\s*|\n", text) if item.strip()}
    return expected <= present


def not_after(path: Path) -> datetime.datetime | None:
    if not path.is_file():
        return None
    result = subprocess.run(
        [OPENSSL, "x509", "-in", str(path), "-noout", "-enddate"],
        capture_output=True, text=True, check=True,
    )
    return parse_enddate(result.stdout)


def subject_alt_names(path: Path) -> str:
    result = subprocess.run(
        [OPENSSL, "x509", "-in", str(path), "-noout", "-ext", "subjectAltName"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout


def run(command: list[str]) -> None:
    subprocess.run(command, check=True, capture_output=True)


def generate(directory: Path, ca_days: int) -> None:
    """Create the CA and sign a leaf; caller guarantees the directory exists."""
    key = directory / "ca.key"
    ca = directory / "ca.pem"
    if not (key.is_file() and ca.is_file()):
        run([
            OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", str(key), "-out", str(ca), "-days", str(ca_days),
            "-subj", "/CN=Panel Local CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        ])
        key.chmod(0o600)
        ca.chmod(0o644)


def issue(directory: Path, addresses: list[str], names: list[str], certificate_days: int) -> None:
    server_key = directory / "server.key"
    certificate = directory / "server.pem"
    request = directory / "server.csr"
    extensions = directory / "server.ext"
    run([
        OPENSSL, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(server_key), "-out", str(request),
        "-subj", "/CN=localhost",
    ])
    server_key.chmod(0o600)
    alt = ",".join([f"IP:{address}" for address in addresses] + [f"DNS:{name}" for name in names])
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={alt}\n"
        "authorityKeyIdentifier=keyid,issuer\n"
        "subjectKeyIdentifier=hash\n"
    )
    run([
        OPENSSL, "x509", "-req", "-in", str(request), "-CA", str(directory / "ca.pem"),
        "-CAkey", str(directory / "ca.key"), "-CAcreateserial",
        "-out", str(certificate), "-days", str(certificate_days), "-extfile", str(extensions),
    ])
    certificate.chmod(0o644)
    request.unlink()
    extensions.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue or renew the loopback panel certificate")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--address", action="append", default=[])
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--ca-days", type=int, default=3650)
    parser.add_argument("--certificate-days", type=int, default=397)
    parser.add_argument("--renew-before-days", type=int, default=30)
    parser.add_argument("--now", help="ISO-8601 instant, for deterministic tests")
    arguments = parser.parse_args()

    directory: Path = arguments.directory
    if not directory.is_dir():
        print(f"panel_proxy_tls: directory {directory} does not exist", file=sys.stderr)
        return 2
    addresses = arguments.address or ["127.0.0.1"]
    names = arguments.name or ["localhost"]
    now = (
        datetime.datetime.fromisoformat(arguments.now).replace(tzinfo=datetime.timezone.utc)
        if arguments.now else datetime.datetime.now(datetime.timezone.utc)
    )

    certificate = directory / "server.pem"
    ca_created = not (directory / "ca.pem").is_file()
    expires_at = not_after(certificate) if certificate.is_file() else None
    valid_identity = expires_at is not None and san_matches(
        subject_alt_names(certificate), addresses, names
    )
    renewed = ca_created or expires_at is None or not valid_identity or needs_renewal(
        expires_at, now, arguments.renew_before_days
    )

    if ca_created:
        generate(directory, arguments.ca_days)
    if renewed:
        issue(directory, addresses, names, arguments.certificate_days)
    expires_at = not_after(certificate)
    print(json.dumps({
        "changed": ca_created or renewed,
        "ca_created": ca_created,
        "certificate_issued": renewed,
        "not_after": expires_at.isoformat() if expires_at else None,
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", "replace").strip() if error.stderr else ""
        print(f"panel_proxy_tls: openssl failed: {detail[:400]}", file=sys.stderr)
        raise SystemExit(1)

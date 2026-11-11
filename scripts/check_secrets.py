"""Офлайн-проверка индекса Git на открытый секретный материал.

Проверяются записи `git ls-files -z` (tracked и staged new). Содержимое берётся
из индекса, а не из рабочего дерева: проверяется то, что попадёт в коммит.
Вывод содержит только имя правила и путь, без содержимого файлов.
"""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

import yaml

from check_repository import private_path

# Литералы маркеров в исходнике разбиты классами символов, чтобы этот файл
# не срабатывал на собственные правила и detect-private-key.
AGE_SECRET_KEY = re.compile(rb"AGE-SECRET-KEY-[1]", re.IGNORECASE)
PRIVATE_KEY_BLOCK = re.compile(rb"-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE[ ]KEY")
AGE_RECIPIENT = re.compile(r"age1[02-9ac-hj-np-z]{58}")
AGE_ENCRYPTED_BLOCK = "-----BEGIN AGE ENCRYPTED FILE-----"
SOPS_MAC = re.compile(r"ENC\[AES256_GCM,data:[^\]]+\]")
SOPS_SUFFIXES = (".sops.yaml", ".sops.yml")


def is_sops_file(path: PurePosixPath) -> bool:
    # `.sops.yaml` — конфигурация sops, а не зашифрованный файл.
    return path.name.endswith(SOPS_SUFFIXES) and path.name not in {".sops.yaml", ".sops.yml"}


def valid_sops_envelope(content: bytes) -> bool:
    try:
        # BaseLoader оставляет скаляры строками (lastmodified не становится datetime).
        document = yaml.load(content.decode("utf-8"), Loader=yaml.BaseLoader)
    except (UnicodeError, yaml.YAMLError):
        return False
    if not isinstance(document, dict) or not isinstance(document.get("sops"), dict):
        return False
    metadata = document["sops"]
    recipients = metadata.get("age")
    if not isinstance(recipients, list) or not recipients:
        return False
    for entry in recipients:
        if not isinstance(entry, dict):
            return False
        recipient, enc = entry.get("recipient"), entry.get("enc")
        if not isinstance(recipient, str) or not AGE_RECIPIENT.fullmatch(recipient):
            return False
        if not isinstance(enc, str) or AGE_ENCRYPTED_BLOCK not in enc:
            return False
    mac = metadata.get("mac")
    if not isinstance(mac, str) or not SOPS_MAC.fullmatch(mac):
        return False
    lastmodified = metadata.get("lastmodified")
    return isinstance(lastmodified, str) and bool(lastmodified.strip())


def content_findings(path: PurePosixPath, content: bytes) -> list[str]:
    rules = []
    if AGE_SECRET_KEY.search(content):
        rules.append("age-secret-key")
    if PRIVATE_KEY_BLOCK.search(content):
        rules.append("private-key-block")
    if is_sops_file(path) and not valid_sops_envelope(content):
        rules.append("sops-envelope")
    return rules


def read_blobs(root: Path, object_ids: list[bytes]) -> dict[bytes, bytes]:
    if not object_ids:
        return {}
    output = subprocess.run(
        ["git", "cat-file", "--batch"], cwd=root, check=True, capture_output=True,
        input=b"".join(object_id + b"\n" for object_id in object_ids),
    ).stdout
    blobs: dict[bytes, bytes] = {}
    position = 0
    for object_id in object_ids:
        header_end = output.index(b"\n", position)
        header = output[position:header_end].split()
        if len(header) != 3:
            raise ValueError("unexpected git cat-file output")
        size = int(header[2])
        start = header_end + 1
        blobs[object_id] = output[start:start + size]
        position = start + size + 1
    return blobs


def scan(root: Path) -> tuple[int, list[tuple[str, str]]]:
    """Возвращает число проверенных путей и пары (правило, путь)."""
    entries = subprocess.check_output(["git", "ls-files", "--cached", "--stage", "-z"], cwd=root)
    findings: list[tuple[str, str]] = []
    pending: list[tuple[PurePosixPath, str, bytes]] = []
    names = set()
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, object_id, _stage = metadata.split()
        name = raw_path.decode("utf-8", errors="surrogateescape")
        names.add(name)
        path = PurePosixPath(name)
        if private_path(path):
            # Содержимое приватных путей не читается вообще.
            findings.append(("private-path", name))
        elif mode != b"160000":
            pending.append((path, name, object_id))

    blobs = read_blobs(root, sorted({object_id for _, _, object_id in pending}))
    for path, name, object_id in pending:
        findings.extend((rule, name) for rule in content_findings(path, blobs[object_id]))
    return len(names), sorted(set(findings), key=lambda item: (item[1], item[0]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="корень рабочего клона Git")
    args = parser.parse_args(argv)
    try:
        count, findings = scan(args.root)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print("Не удалось прочитать индекс Git.", file=sys.stderr)
        return 1
    if findings:
        lines = "\n".join(f"{rule}: {name!r}" for rule, name in findings)
        print("Секретный материал в индексе Git:\n" + lines, file=sys.stderr)
        return 1
    print(f"Проверены на секреты файлы индекса: {count}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

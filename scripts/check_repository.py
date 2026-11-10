"""Проверка публичных путей в индексе и безопасной конфигурации CI."""

from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

import yaml


PRIVATE_NAMES = {
    "readme.local.md",
    "cdn_ipv6_test_plan.md",
    "cdn_ipv6_test_runbook.md",
    "age-keys.txt",
}
PRIVATE_DIRECTORIES = {
    "chats", "local", "private", "secrets", "credentials", "backups",
    "artifacts", "reports", "production", ".ssh", ".aws", ".venv",
}
PRIVATE_PATTERNS = (
    "*.key", "*.pem", "*.p12", "*.pfx", "*.agekey", "id_rsa*", "id_ed25519*",
    "*.db", "*.db-*", "*.sqlite", "*.sqlite-*", "*.sqlite3", "*.sqlite3-*",
    "*.sql", "*.dump", "*.pcap", "*.pcapng", "*.log",
    "*.zip", "*.tar", "*.gz", "*.tgz", "*.bz2", "*.xz", "*.7z", "*.rar",
)
ACTION_REF = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")


def private_path(path: PurePosixPath) -> bool:
    parts = tuple(part.lower() for part in path.parts)
    name = parts[-1]
    if name in PRIVATE_NAMES or PRIVATE_DIRECTORIES.intersection(parts[:-1]):
        return True
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in PRIVATE_PATTERNS):
        return True
    if any(part in {"inventory", "inventories"} for part in parts):
        return any(re.search(r"(^|[._-])(prod|production|live)([._-]|$)", part) for part in parts)
    return False


def workflow_errors(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
        # BaseLoader сохраняет ключ GitHub Actions `on` строкой (не YAML 1.1 bool).
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
    except (OSError, UnicodeError, yaml.YAMLError):
        return ["не удалось разобрать workflow как UTF-8 YAML"]
    if not isinstance(workflow, dict):
        return ["workflow должен быть YAML mapping"]

    errors = []
    events = workflow.get("on")
    if not isinstance(events, dict) or set(events) != {"pull_request", "push"}:
        errors.append("разрешены только обязательные события pull_request и push")
    else:
        if events["pull_request"] not in (None, "", {}):
            errors.append("pull_request должен запускаться без фильтров")
        if events["push"] != {"branches": ["master"]}:
            errors.append("push должен запускаться для master без дополнительных фильтров")
    if workflow.get("permissions") != {"contents": "read"}:
        errors.append("workflow требует permissions: {contents: read}")
    if re.search(r"\bsecrets\s*(?:\.|\[)", text):
        errors.append("workflow не должен обращаться к secrets")
    concurrency = workflow.get("concurrency")
    if not isinstance(concurrency, dict) or concurrency.get("cancel-in-progress") != "true":
        errors.append("workflow требует concurrency с cancel-in-progress: true")

    def inspect(node: object) -> None:
        if isinstance(node, dict):
            if "uses" in node:
                ref = node["uses"]
                if not isinstance(ref, str) or not ACTION_REF.fullmatch(ref):
                    errors.append("каждый uses должен ссылаться на внешний action по полному commit SHA")
                elif ref.startswith("actions/checkout@"):
                    options = node.get("with", {})
                    if not isinstance(options, dict) or options.get("persist-credentials") != "false":
                        errors.append("checkout требует persist-credentials: false")
            if "permissions" in node and node["permissions"] != {"contents": "read"}:
                errors.append("permissions нельзя расширять сверх contents: read")
            for value in node.values():
                inspect(value)
        elif isinstance(node, list):
            for value in node:
                inspect(value)

    inspect(workflow)
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        errors.append("workflow должен содержать jobs")
    else:
        for job in jobs.values():
            if not isinstance(job, dict):
                errors.append("job должен быть YAML mapping")
                continue
            timeout = job.get("timeout-minutes", "")
            if not isinstance(timeout, str) or not timeout.isdigit() or not 1 <= int(timeout) <= 30:
                errors.append("каждый job требует timeout-minutes от 1 до 30")
    return errors


def main() -> int:
    try:
        entries = subprocess.check_output(["git", "ls-files", "--cached", "--stage", "-z"])
    except (OSError, subprocess.CalledProcessError):
        print("Не удалось прочитать индекс Git.", file=sys.stderr)
        return 1

    paths = []
    errors = []
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, _, stage = metadata.split()
        name = raw_path.decode("utf-8", errors="surrogateescape")
        path = PurePosixPath(name)
        if private_path(path):
            errors.append(f"{name!r}: приватный путь, credentials, архив или дамп запрещён")
        elif mode not in {b"100644", b"100755"} or Path(name).is_symlink():
            errors.append(f"{name!r}: symlink/submodule запрещён в публичном репозитории")
        elif stage != b"0":
            errors.append(f"{name!r}: неразрешённый конфликт индекса")
        else:
            paths.append(path)

    # Сначала только имена: содержимое запрещённых файлов не читается вообще.
    if not errors:
        for path in paths:
            if path.parent == PurePosixPath(".github/workflows") and path.suffix in {".yml", ".yaml"}:
                errors.extend(f"{str(path)!r}: {error}" for error in workflow_errors(Path(path)))
    if errors:
        print("Публикация заблокирована:\n" + "\n".join(errors), file=sys.stderr)
        return 1
    print(f"Проверены публичные пути индекса: {len(paths)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

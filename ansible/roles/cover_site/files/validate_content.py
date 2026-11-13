#!/usr/bin/env python3
# Managed by cover_site. Operator static content validation.
"""Validate a complete operator-owned static tree; emit only its public manifest."""
from __future__ import annotations

import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []
        self.text = []
        self.title = []
        self.in_title = False
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        if tag in ("script", "style"):
            self.hidden += 1
        for key, value in attrs:
            if key in ("src", "href", "xlink:href", "poster", "action", "data") and value:
                self.references.append(value)
            if key == "srcset" and value:
                self.references.extend(item.strip().split()[0] for item in value.split(","))
            if key == "style" and value:
                self.references.extend(re.findall(r"url\(\s*['\"]?([^)'\"\s]+)", value))
        if tag in ("iframe", "object", "embed", "form"):
            raise ValueError("The cover must be a self-contained static site, not an embedded service")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)
        if self.hidden:
            if re.search(r"(?:https?:)?//[A-Za-z0-9]", data):
                raise ValueError("Embedded scripts/styles must not contact external services")
            self.references.extend(re.findall(r"url\(\s*['\"]?([^)'\"\s]+)", data))
        if not self.hidden:
            self.text.append(data)


def validate(root: Path) -> list[str]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("cover_site_source must be a real directory")
    paths = sorted(root.rglob("*"))
    files = []
    for path in paths:
        relative = path.relative_to(root)
        if path.is_symlink() or any(part.startswith(".") for part in relative.parts):
            raise ValueError("Symlinks and hidden files are not static cover content")
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", relative.as_posix()):
            raise ValueError("Use portable static filenames without nginx configuration characters")
        if path.is_file():
            if path.suffix.lower() not in {".html", ".htm", ".css", ".js", ".json", ".txt", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".avif"}:
                raise ValueError("Unexpected file type in the public static tree")
            files.append(relative.as_posix())
    if "index.html" not in files:
        raise ValueError("A meaningful index.html is required")
    index = Page()
    index.feed((root / "index.html").read_text(encoding="utf-8"))
    if not "".join(index.title).strip() or len(" ".join(index.text).strip()) < 80:
        raise ValueError("Supply an actual titled static page, not an empty health/placeholder response")
    for name in files:
        path = root / name
        references = []
        if path.suffix.lower() in (".html", ".htm", ".svg"):
            page = Page()
            page.feed(path.read_text(encoding="utf-8"))
            references = page.references
        elif path.suffix.lower() in (".css", ".js"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"(?:https?:)?//[A-Za-z0-9]", text):
                raise ValueError("Static resources must not contact external services")
            references = re.findall(r"url\(\s*['\"]?([^)'\"\s]+)", text)
            references.extend(re.findall(r"@import\s+['\"]([^'\"]+)", text))
        for reference in references:
            url = urlsplit(reference)
            if url.scheme or url.netloc:
                raise ValueError("All links/resources must be local: no trackers, panel or upstream links")
            if not url.path:
                continue
            target = (root / unquote(url.path).lstrip("/")) if url.path.startswith("/") else path.parent / unquote(url.path)
            target = target.resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError("Static reference escapes the site root")
            if target.is_dir():
                target = target / "index.html"
            if not target.is_file():
                raise ValueError("Referenced local static resource does not exist")
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--manifest", action="store_true")
    args = parser.parse_args()
    try:
        files = validate(args.root)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Invalid static cover content: {error}\n")
    print(json.dumps(files) if args.manifest else "Static content and local resources validated")


if __name__ == "__main__":
    main()

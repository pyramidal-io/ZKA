#!/usr/bin/env python3
"""Fail-closed relative-link checker for the public ZKA snapshot.

Scans every tracked Markdown file for inline links and images. Each relative
link must resolve to a tracked path in the snapshot, unless its resolved
target is explicitly declared in .github/doc-link-exceptions.txt (references
to private-side material that is intentionally outside the published scope).
Unused exception entries fail the check so the list cannot rot.
"""

from __future__ import annotations

import posixpath
import re
import subprocess
import sys

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
EXCEPTIONS_PATH = ".github/doc-link-exceptions.txt"
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True, text=True
    ).stdout
    return [p for p in out.split("\0") if p]


def load_exceptions() -> set[str]:
    exceptions: set[str] = set()
    try:
        with open(EXCEPTIONS_PATH, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if line and not line.startswith("#"):
                    exceptions.add(line.rstrip("/"))
    except FileNotFoundError:
        pass
    return exceptions


def main() -> int:
    tracked = tracked_files()
    tracked_set = set(tracked)
    tracked_dirs = {posixpath.dirname(p) for p in tracked_set if posixpath.dirname(p)}
    exceptions = load_exceptions()
    used_exceptions: set[str] = set()
    errors: list[str] = []

    for path in tracked:
        if not path.endswith(".md"):
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        base = posixpath.dirname(path)
        for match in LINK_RE.finditer(text):
            target = match.group(1)
            if target.startswith(SKIP_PREFIXES):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = posixpath.normpath(posixpath.join(base, target)).rstrip("/")
            if resolved.startswith(".."):
                resolved = posixpath.normpath(target).rstrip("/")
            if resolved in tracked_set or resolved in tracked_dirs:
                continue
            if resolved in exceptions:
                used_exceptions.add(resolved)
                continue
            errors.append(f"{path}: unresolved relative link -> {target} ({resolved})")

    for unused in sorted(exceptions - used_exceptions):
        errors.append(f"{EXCEPTIONS_PATH}: unused exception entry -> {unused}")

    if errors:
        for error in errors:
            print(f"::error::{error}", file=sys.stderr)
        return 1

    print("documentation links verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

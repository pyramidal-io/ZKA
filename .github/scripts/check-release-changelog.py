#!/usr/bin/env python3
"""Fail closed unless a release tag matches the spec and public changelog."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


SPEC_VERSION_RE = re.compile(r"^\*\*Version:\*\*\s+([^\s]+)$", re.MULTILINE)
CHANGELOG_RELEASE_RE = re.compile(
    r"^## \[([^\]]+)\] - \d{4}-\d{2}-\d{2}$", re.MULTILINE
)
RELEASE_NOTES_VERSION_RE = re.compile(r"^# ZKA ([^\s]+) release notes$", re.MULTILINE)
EXPECTED_SOURCE_FILES = {
    "zka": {".noir-version", "docs/zka_specification.md"},
    "zkc": {".noir-version", "docs/zkc_specification.md"},
    "afp": {"docs/afp_specification.md", "protocol-family/snapshot-lock.json"},
    "zkm": {
        ".noir-version",
        "docs/zkm_specification.md",
        "protocol-family/zkm-statement-registry-v1.json",
    },
    "zka-langgraph": {"pyproject.toml", "src/zka_langgraph/capabilities/zkm.py"},
}
EXPECTED_SOURCE_VERSIONS = {
    "zka": {"zka"},
    "zkc": {"zkc"},
    "afp": {"afp", "kdc"},
    "zkm": {"zkm"},
    "zka-langgraph": {"zka-langgraph"},
}
PENDING_PUBLICATION_KEYS = {
    "source",
    "target_epoch",
    "target_version",
    "predecessor_version",
}


def fail(message: str) -> None:
    print(f"release changelog invalid: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_output(root: pathlib.Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        fail(f"source revision verification failed: {' '.join(args)}: {detail}")
    return result.stdout


def validate_source_lock(source_lock: object) -> dict[str, object]:
    if not isinstance(source_lock, dict):
        fail("launch source lock must be an object")
    lock_format = source_lock.get("format")
    expected_keys = {"format", "reviewed_on", "sources"}
    observed_keys = set(source_lock)
    if lock_format == "zka:launch-source-lock:v1":
        allowed_keys = {
            frozenset(expected_keys),
            frozenset(expected_keys | {"pending_republish"}),
        }
        source_keys = {"commit", "files"}
    elif lock_format == "zka:launch-source-lock:v2":
        allowed_keys = {
            frozenset(expected_keys),
            frozenset(expected_keys | {"pending_publications"}),
        }
        source_keys = {"commit", "files", "versions"}
    else:
        fail("launch source lock has an unexpected format")
    if frozenset(observed_keys) not in allowed_keys:
        fail(f"launch source lock has unexpected keys: {sorted(observed_keys)!r}")
    reviewed_on = source_lock.get("reviewed_on")
    if not isinstance(reviewed_on, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_on) is None:
        fail("launch source lock reviewed_on must be YYYY-MM-DD")
    sources = source_lock.get("sources")
    if not isinstance(sources, dict) or set(sources) != set(EXPECTED_SOURCE_FILES):
        fail("launch source lock has an unexpected source set")
    for name, expected_files in EXPECTED_SOURCE_FILES.items():
        source = sources.get(name)
        if not isinstance(source, dict) or set(source) != source_keys:
            fail(f"launch source lock has a malformed {name} source")
        commit = source.get("commit")
        files = source.get("files")
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            fail(f"launch source lock has a malformed {name} commit")
        if not isinstance(files, dict) or set(files) != expected_files:
            fail(f"launch source lock has malformed {name} source files")
        for path, digest in files.items():
            if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                fail(f"launch source lock has a malformed digest for {name}:{path}")
        if lock_format == "zka:launch-source-lock:v2":
            versions = source.get("versions")
            if not isinstance(versions, dict) or set(versions) != EXPECTED_SOURCE_VERSIONS[name]:
                fail(f"launch source lock has malformed {name} source versions")
            if not all(isinstance(version, str) and version for version in versions.values()):
                fail(f"launch source lock has malformed {name} source version values")
    raw_publications: object
    if lock_format == "zka:launch-source-lock:v1" and "pending_republish" in source_lock:
        raw_publications = [source_lock["pending_republish"]]
    elif lock_format == "zka:launch-source-lock:v2" and "pending_publications" in source_lock:
        raw_publications = source_lock["pending_publications"]
        if not isinstance(raw_publications, list) or not raw_publications:
            fail("launch source lock pending_publications must be a non-empty list")
    else:
        raw_publications = []
    assert isinstance(raw_publications, list)
    pending_sources: set[str] = set()
    for pending in raw_publications:
        if not isinstance(pending, dict) or set(pending) != PENDING_PUBLICATION_KEYS:
            fail("launch source lock has malformed pending publication")
        if not all(isinstance(value, str) and value for value in pending.values()):
            fail("launch source lock has malformed pending publication values")
        source = pending["source"]
        if lock_format == "zka:launch-source-lock:v1" and source != "zka":
            fail("launch source lock legacy pending source must be zka")
        if source not in sources:
            fail("launch source lock has a pending publication for an unlocked source")
        if source in pending_sources:
            fail("launch source lock names a pending source more than once")
        pending_sources.add(source)
    return source_lock


def verify_tagged_zka_source(
    source_lock: dict[str, object], source_root: pathlib.Path, source_revision: str
) -> None:
    sources = source_lock["sources"]
    assert isinstance(sources, dict)
    zka = sources["zka"]
    assert isinstance(zka, dict)
    pinned_files = zka["files"]
    assert isinstance(pinned_files, dict)

    tag_commit = git_output(source_root, "rev-parse", "--verify", f"{source_revision}^{{commit}}")
    tag_commit = tag_commit.decode().strip()

    for path, expected_digest in pinned_files.items():
        assert isinstance(path, str) and isinstance(expected_digest, str)
        tagged_bytes = git_output(source_root, "show", f"{tag_commit}:{path}")
        observed_digest = "sha256:" + hashlib.sha256(tagged_bytes).hexdigest()
        if observed_digest != expected_digest:
            fail(
                f"tagged ZKA source digest mismatch for {path}: "
                f"expected {expected_digest}, observed {observed_digest}"
            )
    if source_lock["format"] == "zka:launch-source-lock:v2":
        versions = zka["versions"]
        assert isinstance(versions, dict)
        tagged_specification = git_output(
            source_root, "show", f"{tag_commit}:docs/zka_specification.md"
        ).decode("utf-8")
        match = SPEC_VERSION_RE.search(tagged_specification)
        if match is None or match.group(1) != versions["zka"]:
            observed = None if match is None else match.group(1)
            fail(
                "tagged ZKA source version mismatch: "
                f"expected {versions['zka']!r}, observed {observed!r}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--spec", default="docs/zka_specification.md")
    parser.add_argument("--changelog", default="CHANGELOG.md")
    parser.add_argument("--release-notes", default="docs/RELEASE_NOTES.md")
    parser.add_argument(
        "--source-lock", default="protocol-family/launch-source-lock-v2.json"
    )
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--source-revision", default="HEAD")
    args = parser.parse_args()

    if not args.tag.startswith("v") or len(args.tag) == 1:
        fail(f"release tag must have form v<spec-version>, got {args.tag!r}")
    tag_version = args.tag[1:]

    spec_text = pathlib.Path(args.spec).read_text(encoding="utf-8")
    match = SPEC_VERSION_RE.search(spec_text)
    if match is None:
        fail("specification has no canonical Version header")
    spec_version = match.group(1)
    if tag_version != spec_version:
        fail(
            f"tag {args.tag} does not match specification version {spec_version}"
        )

    changelog_text = pathlib.Path(args.changelog).read_text(encoding="utf-8")
    releases = CHANGELOG_RELEASE_RE.findall(changelog_text)
    if spec_version not in releases:
        fail(
            f"specification version {spec_version} has no matching public changelog entry"
        )

    release_notes_text = pathlib.Path(args.release_notes).read_text(encoding="utf-8")
    release_notes_match = RELEASE_NOTES_VERSION_RE.search(release_notes_text)
    if release_notes_match is None:
        fail("release notes have no canonical ZKA version heading")
    release_notes_version = release_notes_match.group(1)
    if release_notes_version != spec_version:
        fail(
            "release notes version "
            f"{release_notes_version} does not match specification version {spec_version}"
        )

    try:
        source_lock = json.loads(pathlib.Path(args.source_lock).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"launch source lock is unreadable: {exc}")
    source_lock = validate_source_lock(source_lock)
    if "pending_republish" in source_lock or "pending_publications" in source_lock:
        fail("launch source lock still has pending post-merge publications")
    if source_lock["format"] == "zka:launch-source-lock:v2":
        sources = source_lock["sources"]
        assert isinstance(sources, dict)
        zka = sources["zka"]
        assert isinstance(zka, dict)
        versions = zka["versions"]
        assert isinstance(versions, dict)
        if versions["zka"] != spec_version:
            fail(
                "launch source lock ZKA version "
                f"{versions['zka']} does not match specification version {spec_version}"
            )
    verify_tagged_zka_source(
        source_lock, pathlib.Path(args.source_root).resolve(), args.source_revision
    )

    print(f"release changelog valid: {args.tag} -> {spec_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

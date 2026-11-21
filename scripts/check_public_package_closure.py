#!/usr/bin/env python3
"""Check local Noir/Cargo package closure in a materialized public snapshot.

This offline structural gate checks exact workspace members, local dependency
manifests, package entrypoints, conventional out-of-line modules, and literal
Rust include!/include_str!/include_bytes! inputs. It never fetches dependencies
or compiles code. Compiler and test gates remain necessary: macro expansion,
feature semantics, and generated source are outside this bounded check. Custom
module paths and computed includes fail closed instead of being guessed.
Requires Python 3.11+; no third-party modules.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import tomllib


class ClosureError(ValueError):
    """A package reference cannot be satisfied inside the snapshot."""


# Keep strings as single tokens so source-looking text in strings cannot create
# module references. Block comments can nest in both source languages.
TOKEN = re.compile(
    r'(?P<space>\s+)|(?P<line>//[^\n]*)|(?P<block>/\*)|'
    r'(?P<raw>(?:br|r)(?P<hashes>\#*)"[\s\S]*?"(?P=hashes))|'
    r'(?P<string>b?"(?:\\.|[^"\\])*")|'
    r"(?P<char>b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])')|"
    r'(?P<ident>[A-Za-z_][A-Za-z_0-9]*)|(?P<punct>.)',
    re.DOTALL,
)


def tokens(contents: str) -> list[str]:
    result = []
    offset = 0
    while offset < len(contents):
        match = TOKEN.match(contents, offset)
        assert match is not None
        offset = match.end()
        if match.lastgroup == "block":
            depth = 1
            while depth:
                boundary = re.search(r'/\*|\*/', contents[offset:])
                if boundary is None:
                    raise ClosureError("unterminated block comment")
                depth += 1 if boundary.group() == "/*" else -1
                offset += boundary.end()
        elif match.lastgroup not in {"space", "line"}:
            result.append(match.group())
    return result


class Snapshot:
    def __init__(self, root: pathlib.Path):
        self.root = root.resolve(strict=True)
        self.entrypoints: set[pathlib.Path] = set()
        if not self.root.is_dir():
            raise ClosureError("snapshot root must be a directory")

    def label(self, path: pathlib.Path) -> str:
        return path.relative_to(self.root).as_posix()

    def local(self, base: pathlib.Path, raw: str) -> pathlib.Path:
        if not isinstance(raw, str) or not raw or "\\" in raw or pathlib.PurePosixPath(raw).is_absolute():
            raise ClosureError(f"invalid relative package path: {raw!r}")
        # Inspect lexical components before normalizing `..`: otherwise a
        # symlink followed by `..` could disappear from the safety check.
        current = base
        for part in pathlib.PurePosixPath(raw).parts:
            current = current.parent if part == ".." else current / part
            if current.is_symlink():
                raise ClosureError(f"symlink in package reference: {raw}")
        path = pathlib.Path(os.path.normpath(base / raw))
        if not path.is_relative_to(self.root):
            raise ClosureError(f"path escapes snapshot: {raw}")
        relative = path.relative_to(self.root)
        if any(part.casefold() == ".git" for part in relative.parts):
            raise ClosureError(f"package reference enters .git: {raw}")
        current = self.root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ClosureError(f"symlink in package reference: {self.label(current)}")
        return path

    def require(self, path: pathlib.Path, reason: str) -> None:
        self.local(path.parent, path.name)
        if not path.is_file():
            raise ClosureError(f"{reason}: missing file {self.label(path)}")

    def manifest(self, path: pathlib.Path) -> dict:
        self.require(path, "package manifest")
        with path.open("rb") as source:
            return tomllib.load(source)

    def workspace_manifest(self, manifest: pathlib.Path) -> dict:
        parent = manifest.parent
        while parent.is_relative_to(self.root):
            candidate = parent / "Cargo.toml"
            if candidate.is_file():
                document = self.manifest(candidate)
                if "workspace" in document:
                    return document
            if parent == self.root:
                break
            parent = parent.parent
        raise ClosureError(f"{self.label(manifest)}: workspace inheritance has no workspace")

    def dependencies(self, document: dict, manifest: pathlib.Path) -> None:
        def visit(table: dict) -> None:
            for key, value in table.items():
                if key in {"dependencies", "dev-dependencies", "build-dependencies", "patch", "replace"}:
                    check_table(value)
                elif key in {"target", "workspace"} and isinstance(value, dict):
                    # target contains a table per platform; workspace contains
                    # dependencies directly. Recurse without interpreting metadata.
                    visit(value)
                    if key == "target":
                        for platform in value.values():
                            if isinstance(platform, dict):
                                visit(platform)

        def check_table(table: dict) -> None:
            if not isinstance(table, dict):
                raise ClosureError(f"{self.label(manifest)}: malformed dependencies")
            for name, dependency in table.items():
                if not isinstance(dependency, dict):
                    continue  # Registry version string.
                if "path" in dependency:
                    target = self.local(manifest.parent, dependency["path"]) / manifest.name
                    self.require(target, f"{self.label(manifest)} dependency {name}")
                if dependency.get("workspace") is True:
                    inherited = self.workspace_manifest(manifest).get("workspace", {}).get("dependencies", {})
                    if name not in inherited:
                        raise ClosureError(f"{self.label(manifest)}: missing workspace dependency {name}")
                if manifest.name == "Cargo.toml" and "path" not in dependency:
                    # Cargo patch tables have an extra registry nesting level.
                    if not any(key in dependency for key in ("version", "git", "workspace", "registry", "package")):
                        check_table(dependency)
        visit(document)

    def check_manifest(self, path: pathlib.Path) -> None:
        document = self.manifest(path)
        workspace = document.get("workspace", {})
        for field in ("members", "default-members"):
            for member in workspace.get(field, []):
                if not isinstance(member, str) or any(char in member for char in "*?[]"):
                    raise ClosureError(f"{self.label(path)}: workspace {field} must use exact relative paths")
                self.require(self.local(path.parent, member) / path.name, f"{self.label(path)} workspace member")
        self.dependencies(document, path)
        if "package" not in document:
            if "workspace" not in document:
                raise ClosureError(f"{self.label(path)} has neither package nor workspace")
            return
        if path.name == "Nargo.toml":
            kind = document["package"].get("type")
            if kind not in {"lib", "bin", "contract"}:
                raise ClosureError(f"{self.label(path)}: unsupported Noir package type {kind!r}")
            entry = "src/lib.nr" if kind == "lib" else "src/main.nr"
            target = self.local(path.parent, entry)
            self.require(target, f"{self.label(path)} entrypoint")
            self.entrypoints.add(target)
            return
        if document["package"].get("workspace") is not None:
            raise ClosureError(f"{self.label(path)}: explicit Cargo package.workspace requires review")
        entries = []
        if "lib" in document:
            entries.append(document["lib"].get("path", "src/lib.rs"))
        elif (path.parent / "src/lib.rs").is_file():
            entries.append("src/lib.rs")
        if (path.parent / "src/main.rs").is_file():
            entries.append("src/main.rs")
        for kind, directory in (("bin", "src/bin"), ("test", "tests"), ("bench", "benches"), ("example", "examples")):
            for target in document.get(kind, []):
                entry = target.get("path")
                if entry is None:
                    name = target.get("name")
                    if not isinstance(name, str):
                        raise ClosureError(f"{self.label(path)}: {kind} target needs name or path")
                    entry = f"{directory}/{name}.rs"
                    if not (path.parent / entry).is_file():
                        entry = f"{directory}/{name}/main.rs"
                entries.append(entry)
        if not entries:
            raise ClosureError(f"{self.label(path)}: no supported Cargo library or binary entrypoint")
        build = document["package"].get("build")
        if isinstance(build, str):
            entries.append(build)
        for entry in entries:
            target = self.local(path.parent, entry)
            self.require(target, f"{self.label(path)} entrypoint")
            self.entrypoints.add(target)

    def check_source(self, path: pathlib.Path) -> None:
        self.require(path, "package source")
        source = tokens(path.read_text(encoding="utf-8"))
        base = path.parent if path in self.entrypoints or path.stem in {"lib", "main", "mod"} else path.with_suffix("")
        scopes = [base]
        index = 0
        while index < len(source):
            token = source[index]
            if source[index:index + 2] == ["#", "["]:
                end = index + 2
                while end < len(source) and source[end] != "]":
                    if source[end:end + 2] == ["path", "="]:
                        raise ClosureError(f"{self.label(path)}: custom module path requires review")
                    end += 1
            if token == "mod" and index + 2 < len(source) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", source[index + 1]):
                name, delimiter = source[index + 1:index + 3]
                if delimiter == ";":
                    candidates = [scopes[-1] / f"{name}{path.suffix}", scopes[-1] / name / f"mod{path.suffix}"]
                    for candidate in candidates:
                        self.local(candidate.parent, candidate.name)
                    present = [candidate for candidate in candidates if candidate.is_file()]
                    if len(present) != 1:
                        raise ClosureError(f"{self.label(path)}: module {name} needs exactly one source file ({', '.join(self.label(p) for p in candidates)})")
                elif delimiter == "{":
                    # Noir inline modules keep the enclosing file's lookup
                    # directory; Rust inline modules introduce a directory.
                    scopes.append(scopes[-1] / name if path.suffix == ".rs" else scopes[-1])
                    index += 3
                    continue
            if token in {"include", "include_str", "include_bytes"} and source[index + 1:index + 2] == ["!"]:
                tail = source[index + 3:]
                if (
                    source[index + 2:index + 3] != ["("]
                    or len(tail) < 2
                    or not re.fullmatch(r'"[^"\\]*"', tail[0])
                    or not (tail[1] == ")" or tail[1:3] == [",", ")"])
                ):
                    raise ClosureError(f"{self.label(path)}: computed include requires review")
                self.require(self.local(path.parent, tail[0][1:-1]), f"{self.label(path)} {token} input")
            if token == "{":
                scopes.append(scopes[-1])
            elif token == "}":
                if len(scopes) == 1:
                    raise ClosureError(f"{self.label(path)}: unbalanced source braces")
                scopes.pop()
            index += 1
        if len(scopes) != 1:
            raise ClosureError(f"{self.label(path)}: unbalanced source braces")

    def check(self) -> tuple[int, int]:
        manifests, sources = [], []
        for directory, children, files in os.walk(self.root, followlinks=False):
            children[:] = sorted(child for child in children if child not in {".git", "target"})
            for name in sorted(files):
                path = pathlib.Path(directory) / name
                if name in {"Nargo.toml", "Cargo.toml"}:
                    manifests.append(path)
                elif path.suffix in {".nr", ".rs"}:
                    sources.append(path)
        if not manifests:
            raise ClosureError("snapshot has no Noir or Cargo manifests")
        for path in manifests:
            self.check_manifest(path)
        for path in sources:
            self.check_source(path)
        return len(manifests), len(sources)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    args = parser.parse_args(argv)
    try:
        manifests, sources = Snapshot(args.root).check()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"public package closure invalid: {error}", file=sys.stderr)
        return 1
    print(f"public package closure verified: {manifests} manifests, {sources} source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

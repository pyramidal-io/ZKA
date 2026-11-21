#!/usr/bin/env python3
# Copyright 2026 ZKA Contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate adapter certification manifests against reality.

The manifests in `certification/<adapter>.json` claim which test classes an
adapter passes, with pointers to the tests/CI jobs that prove it (see
docs/certification/adapter_certification.md). This validator FAILS on drift:

  * schema problems (unknown class, unknown status, unknown evidence kind);
  * a claimed tier whose required classes (certification/tiers.json) are not
    all `pass`;
  * a `pass`/`partial` class with no evidence;
  * a `not_applicable`/`missing` class without an explanatory note;
  * evidence that no longer resolves:
      - `test_fn`:    file must exist and contain `fn <name>`
      - `test_file`:  file must exist
      - `forge_test`: .t.sol file must exist and contain `pattern`
      - `ci_job`:     workflow file must exist and reference the job name
      - `path`:       file or directory must exist
  * production/default deployment tooling that can instantiate a retired
    APLBridge settlement path;
  * drift of the bytecode-free ZKABridgeEthereum retirement tombstone, or a
    renamed Solidity implementation that attempts to restore that contract.

stdlib only; run from anywhere inside the repo:

    python3 scripts/validate-certification.py

Public snapshots intentionally omit the private retirement tombstone. Opt in
explicitly; all executable retirement-surface checks still run:

    python3 scripts/validate-certification.py --public-snapshot
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import shlex
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CERT_DIR = REPO / "certification"
MANIFEST_VERSION = "zka:certification:v1"
TIERS_VERSION = "zka:certification-tiers:v1"
STATUSES = {"pass", "partial", "missing", "not_applicable"}
EVIDENCE_KINDS = {"test_fn", "test_file", "forge_test", "ci_job", "path"}

LEGACY_SOLIDITY_IMPORT = re.compile(
    r"\bimport\s+(?:\{[^;]*\}\s+from\s+)?[\"'][^\"']*/"
    r"(?P<contract>APLBridge|ZKABridgeEthereum|MerkleTree)\.sol[\"']",
    re.DOTALL,
)
LEGACY_SOLIDITY_CONSTRUCTION = re.compile(
    r"\bnew\s+(?P<contract>APLBridge|ZKABridgeEthereum|MerkleTree)\s*\("
)
RETIRED_ZKA_BRIDGE_DECLARATION = re.compile(
    r"\b(?:abstract\s+)?contract\s+ZKABridgeEthereum\b"
)
SOLIDITY_NON_CODE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
    re.DOTALL,
)
LEGACY_SHELL_DEPLOYMENTS = {
    "script/DeployAPLBridge.s.sol": "DeployAPLBridge.s.sol",
    "script/Deploy.s.sol": "script/Deploy.s.sol",
    "contracts/ethereum/APLBridge.sol": "APLBridge.sol",
    "contracts/ethereum/ZKABridgeEthereum.sol": "ZKABridgeEthereum.sol",
    "contracts/ethereum/MerkleTree.sol": "MerkleTree.sol",
}
UNRESOLVED_DYNAMIC_SHELL_TARGET = "<unresolved-dynamic-forge-target>"
UNPARSEABLE_SHELL_SOURCE = "<unparseable-shell-source>"
SHELL_VARIABLE_TARGET = re.compile(
    r"^\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))$"
)
SHELL_REDIRECTION = re.compile(r"^(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(?:<|>|&>)")
SHELL_PUNCTUATION_CHARS = ";&|\n()`"
FORGE_FLAG_OPTIONS = {
    "--ast",
    "--batch",
    "--blob",
    "--broadcast",
    "--build-info",
    "--debug",
    "--disable-code-size-limit",
    "--disable-labels",
    "--dynamic-test-linking",
    "--eip4844",
    "--force",
    "--hardhat",
    "--help",
    "--json",
    "--legacy",
    "--md",
    "--multi",
    "--no-auto-detect",
    "--no-cache",
    "--no-metadata",
    "--non-interactive",
    "--offline",
    "--quiet",
    "--resume",
    "--show-standard-json-input",
    "--skip-simulation",
    "--slow",
    "--unlocked",
    "--use-literal-content",
    "--verify",
    "--version",
    "--via-ir",
}
FORGE_VALUE_OPTIONS = {
    "--auth",
    "--batch-size",
    "--blob-gas-price",
    "--build-info-path",
    "--cache-path",
    "--color",
    "--config-path",
    "--constructor-args-path",
    "--contracts",
    "--deny",
    "--dump",
    "--etherscan-api-key",
    "--evm-version",
    "--gas-estimate-multiplier",
    "--gas-limit",
    "--gas-price",
    "--jobs",
    "--libraries",
    "--nonce",
    "--optimizer-runs",
    "--out",
    "--priority-gas-price",
    "--private-key",
    "--remappings-env",
    "--revert-strings",
    "--root",
    "--rpc-url",
    "--sig",
    "--target-contract",
    "--tempo.fee-token",
    "--threads",
    "--timeout",
    "--use",
    "--value",
    "--with-gas-price",
}
FORGE_SHORT_FLAG_OPTIONS = {"-h", "-q"}
FORGE_SHORT_VALUE_OPTIONS = {"-C", "-D", "-R", "-g", "-j", "-o", "-s"}
DEPLOYMENT_SCAN_EXCLUDED_DIRS = {
    ".git",
    ".soldeer",
    "broadcast",
    "cache",
    "lib",
    "node_modules",
    "out",
    "target",
}
TEST_ONLY_SMOKE_SCRIPTS = {
    Path("script/AplSettlementSmoke.s.sol"),
}
OPERATIONAL_LEGACY_ATTACH_SCRIPTS = {
    Path("script/APLBridgeLiveSmoke.s.sol"),
}
TEST_ONLY_DYNAMIC_SHELL_SCRIPTS = {
    Path("scripts/apl-settlement-smoke-deploy.sh"),
}
RETIRED_ZKA_BRIDGE_PATH = Path("contracts/ethereum/ZKABridgeEthereum.sol")
RETIRED_ZKA_BRIDGE_SHA256 = (
    "83bab2a51283c08f19fdafc7768b17ff3e9e9c17f4ab0060f03567a658d19274"
)

errors: list[str] = []


def err(manifest: str, message: str) -> None:
    errors.append(f"{manifest}: {message}")


def check_evidence(manifest: str, cls: str, ev: dict) -> None:
    where = f"class `{cls}` evidence {json.dumps(ev, sort_keys=True)}"
    kind = ev.get("kind")
    if kind not in EVIDENCE_KINDS:
        err(manifest, f"{where}: unknown kind `{kind}`")
        return
    if kind == "ci_job":
        workflow = REPO / ev.get("workflow", "")
        if not workflow.is_file():
            err(manifest, f"{where}: workflow does not exist")
            return
        job = ev.get("job", "")
        if not job or job not in workflow.read_text():
            err(manifest, f"{where}: job `{job}` not found in {ev.get('workflow')}")
        return
    path = REPO / ev.get("path", "")
    if not path.exists():
        err(manifest, f"{where}: path does not exist")
        return
    if kind == "test_fn":
        name = ev.get("name", "")
        if not name or f"fn {name}" not in path.read_text():
            err(manifest, f"{where}: `fn {name}` not found in {ev.get('path')}")
    elif kind == "forge_test":
        pattern = ev.get("pattern", "")
        if not pattern or pattern not in path.read_text():
            err(manifest, f"{where}: pattern `{pattern}` not found in {ev.get('path')}")
    elif kind in ("test_file", "path"):
        pass  # existence is the check


def legacy_deployment_errors(
    repo: Path, *, require_retirement_tombstone: bool = False
) -> list[str]:
    """Return executable deployment surfaces for retired settlement designs.

    The ZKABridgeEthereum implementation is a hash-pinned abstract tombstone
    with no creation/runtime bytecode. Its ABI-only Rust observation and exit
    client is intentionally outside this source/deployment scan. The APL smoke
    remains a local harness; production/default deployers must use ZKAEthPool.
    """

    problems: list[str] = []
    tombstone = repo / RETIRED_ZKA_BRIDGE_PATH
    if tombstone.is_file():
        digest = hashlib.sha256(tombstone.read_bytes()).hexdigest()
        if digest != RETIRED_ZKA_BRIDGE_SHA256:
            problems.append(
                f"{RETIRED_ZKA_BRIDGE_PATH} differs from the pinned retirement tombstone"
            )
    elif require_retirement_tombstone:
        problems.append(f"{RETIRED_ZKA_BRIDGE_PATH} retirement tombstone is missing")

    for path in repository_scan_files(repo, "*.sol"):
        relative = path.relative_to(repo)
        if relative == RETIRED_ZKA_BRIDGE_PATH:
            continue
        code = SOLIDITY_NON_CODE.sub(" ", path.read_text())
        if RETIRED_ZKA_BRIDGE_DECLARATION.search(code):
            problems.append(
                f"{relative} defines retired settlement contract `ZKABridgeEthereum`"
            )

    for path in repository_scan_files(repo, "*.s.sol"):
        relative = path.relative_to(repo)
        if relative in TEST_ONLY_SMOKE_SCRIPTS:
            continue
        source = path.read_text()
        imported = {match.group("contract") for match in LEGACY_SOLIDITY_IMPORT.finditer(source)}
        code = SOLIDITY_NON_CODE.sub(" ", source)
        constructed = {
            match.group("contract") for match in LEGACY_SOLIDITY_CONSTRUCTION.finditer(code)
        }
        for contract in sorted(imported | constructed):
            if contract in constructed:
                action = "deploys"
            elif relative not in OPERATIONAL_LEGACY_ATTACH_SCRIPTS:
                action = "imports"
            else:
                continue
            problems.append(f"{relative} {action} retired legacy settlement contract `{contract}`")

    for path in repository_scan_files(repo, "*.sh"):
        relative = path.relative_to(repo)
        for deployer in legacy_shell_deployers(path.read_text()):
            if deployer == UNPARSEABLE_SHELL_SOURCE:
                problems.append(
                    f"{relative} cannot be parsed for Forge deployment targets"
                )
                continue
            if deployer == UNRESOLVED_DYNAMIC_SHELL_TARGET:
                if relative not in TEST_ONLY_DYNAMIC_SHELL_SCRIPTS:
                    problems.append(
                        f"{relative} uses unresolved dynamic Forge deployment target"
                    )
                continue
            problems.append(
                f"{relative} invokes retired legacy settlement deployer `{deployer}`"
            )

    return problems


def repository_scan_files(repo: Path, pattern: str) -> list[Path]:
    """Return repository candidates while excluding root build/vendor trees."""

    return sorted(
        path
        for path in repo.rglob(pattern)
        if path.is_file()
        and path.relative_to(repo).parts[0] not in DEPLOYMENT_SCAN_EXCLUDED_DIRS
    )


def legacy_shell_deployers(source: str) -> list[str]:
    """Return retired or unresolved targets from Forge deployment commands.

    Forge accepts global options before the subcommand and subcommand options
    before the contract/script path. Inspect the complete command segment
    instead of assuming either positional token is adjacent to its predecessor.
    """

    try:
        lexer = shlex.shlex(
            source.replace("\\\n", " "),
            posix=True,
            punctuation_chars=SHELL_PUNCTUATION_CHARS,
        )
        lexer.commenters = "#"
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        # shlex does not implement every Bash construct (notably heredocs).
        # A parse failure must never suppress a deployment finding or inherit
        # the local smoke helper's dynamic-target exemption.
        return [UNPARSEABLE_SHELL_SOURCE]

    deployers: set[str] = set()
    collapsed_substitutions: list[str] = []
    for index, token in enumerate(tokens):
        # POSIX shlex intentionally treats the contents of a quoted command
        # substitution as one token. Re-tokenize just those executable nested
        # fragments so `"$(forge create ...)"` and quoted backticks cannot hide
        # a literal retired target. Assignment-only quoted strings do not meet
        # this delimiter test.
        if "forge" in token and ("$(" in token or "`" in token):
            collapsed_substitutions.append(token)
        if Path(token).name != "forge":
            continue

        command_end = index + 1
        while command_end < len(tokens):
            candidate = tokens[command_end]
            if is_shell_separator_run(candidate) or Path(candidate).name == "forge":
                break
            command_end += 1

        command = tokens[index + 1 : command_end]
        subcommand_index, ambiguous = first_forge_positional(command)
        if ambiguous:
            deployers.add(UNRESOLVED_DYNAMIC_SHELL_TARGET)
            continue
        if subcommand_index is None or command[subcommand_index] not in {
            "create",
            "script",
        }:
            continue

        target = forge_deployment_target(command[subcommand_index + 1 :])
        if target == UNRESOLVED_DYNAMIC_SHELL_TARGET:
            deployers.add(UNRESOLVED_DYNAMIC_SHELL_TARGET)
            continue

        normalized = posixpath.normpath(target.split(":", 1)[0])
        deployer = LEGACY_SHELL_DEPLOYMENTS.get(normalized)
        if deployer:
            deployers.add(deployer)

    for nested_source in collapsed_substitutions:
        nested_deployers = legacy_shell_deployers(nested_source)
        deployers.update(nested_deployers)
    return sorted(deployers)


def is_shell_separator_run(token: str) -> bool:
    """Return whether shlex grouped one or more shell separators in a token."""

    return bool(token) and all(
        character in SHELL_PUNCTUATION_CHARS for character in token
    )


def forge_deployment_target(args: list[str]) -> str:
    """Return the first Forge deployment positional, or fail closed.

    Options after the target are irrelevant. Before the target, known flags
    consume no value and known value options consume exactly one. Unknown,
    optional-value, and variadic options are intentionally unresolved: silently
    guessing their arity could mistake an option value for the deployment path.
    """

    index, ambiguous = first_forge_positional(args)
    if ambiguous or index is None:
        return UNRESOLVED_DYNAMIC_SHELL_TARGET

    target = args[index]
    # Never infer a deployment target from shell assignment state. Pipelines,
    # background lists, conditionals, functions, and inherited environment
    # values make even apparently literal assignments control-flow dependent.
    # A single local-only smoke helper is explicitly quarantined by path; all
    # other dynamic deployment targets fail closed.
    if SHELL_VARIABLE_TARGET.fullmatch(target) or "$" in target or "`" in target:
        return UNRESOLVED_DYNAMIC_SHELL_TARGET
    return target


def first_forge_positional(args: list[str]) -> tuple[int | None, bool]:
    """Return the first positional index and whether option parsing is ambiguous."""

    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token.startswith("--"):
            option, separator, _value = token.partition("=")
            if separator:
                if option in FORGE_VALUE_OPTIONS:
                    index += 1
                    continue
                return None, True
            if option in FORGE_FLAG_OPTIONS:
                index += 1
                continue
            if option in FORGE_VALUE_OPTIONS:
                if index + 1 >= len(args):
                    return None, True
                index += 2
                continue
            return None, True
        if token.startswith("-"):
            if token in FORGE_SHORT_FLAG_OPTIONS or re.fullmatch(r"-v+", token):
                index += 1
                continue
            option = token[:2]
            if option in FORGE_SHORT_VALUE_OPTIONS:
                if len(token) > 2:
                    index += 1
                elif index + 1 < len(args):
                    index += 2
                else:
                    return None, True
                continue
            return None, True
        # Redirections may legally appear before a command positional. Their
        # operands are not deployment targets, and shlex does not provide a
        # complete Bash redirection AST, so ambiguity must fail closed.
        if SHELL_REDIRECTION.match(token):
            return None, True
        break

    if index >= len(args):
        return None, False
    return index, False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--public-snapshot",
        action="store_true",
        help=(
            "allow the private retirement tombstone to be absent; still reject "
            "modified tombstones and executable retired deployment surfaces"
        ),
    )
    args = parser.parse_args()
    for message in legacy_deployment_errors(
        REPO, require_retirement_tombstone=not args.public_snapshot
    ):
        err("deployment-surface", message)

    tiers_path = CERT_DIR / "tiers.json"
    if not tiers_path.is_file():
        print(f"ERROR: {tiers_path} missing", file=sys.stderr)
        return 1
    tiers_doc = json.loads(tiers_path.read_text())
    if tiers_doc.get("version") != TIERS_VERSION:
        print(f"ERROR: tiers.json version is not {TIERS_VERSION}", file=sys.stderr)
        return 1
    classes = set(tiers_doc["classes"])
    tiers = {name: set(spec["required"]) for name, spec in tiers_doc["tiers"].items()}
    for tier, required in tiers.items():
        unknown = required - classes
        if unknown:
            print(f"ERROR: tiers.json tier `{tier}` requires unknown classes {sorted(unknown)}", file=sys.stderr)
            return 1

    manifests = sorted(p for p in CERT_DIR.glob("*.json") if p.name != "tiers.json")
    if not manifests:
        print("ERROR: no certification manifests found", file=sys.stderr)
        return 1

    for path in manifests:
        name = path.name
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            err(name, f"invalid JSON: {e}")
            continue
        if doc.get("version") != MANIFEST_VERSION:
            err(name, f"version must be {MANIFEST_VERSION}")
            continue
        tier = doc.get("tier")
        if tier not in tiers:
            err(name, f"unknown tier `{tier}`")
            continue
        manifest_classes = doc.get("classes", {})
        unknown = set(manifest_classes) - classes
        if unknown:
            err(name, f"unknown classes {sorted(unknown)}")
        missing_rows = classes - set(manifest_classes)
        if missing_rows:
            err(name, f"manifest must cover every class; missing {sorted(missing_rows)}")

        for cls, spec in manifest_classes.items():
            status = spec.get("status")
            if status not in STATUSES:
                err(name, f"class `{cls}`: unknown status `{status}`")
                continue
            evidence = spec.get("evidence", [])
            if status in ("pass", "partial") and not evidence:
                err(name, f"class `{cls}`: status `{status}` requires evidence")
            if status in ("missing", "not_applicable") and not spec.get("notes"):
                err(name, f"class `{cls}`: status `{status}` requires an explanatory `notes`")
            for ev in evidence:
                check_evidence(name, cls, ev)

        # Tier gate: every class the claimed tier requires must be `pass`.
        for cls in sorted(tiers[tier]):
            status = manifest_classes.get(cls, {}).get("status")
            if status != "pass":
                err(
                    name,
                    f"claims tier `{tier}` but required class `{cls}` is `{status}` (must be `pass`)",
                )

    if errors:
        print(f"certification validation FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for e in errors:
            print(f"  DRIFT {e}", file=sys.stderr)
        return 1
    print(f"certification OK: {len(manifests)} manifest(s) validated against the tree")
    for path in manifests:
        doc = json.loads(path.read_text())
        print(f"  {doc['adapter']}: tier={doc['tier']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

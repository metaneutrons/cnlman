#!/usr/bin/env python3
"""Fail unless an SPDX SBOM describes the Rust dependency graph of cnlman.

Release binaries are built with `cargo auditable`, which embeds the resolved
dependency list; syft reads it back into the SBOM. A binary built without it
yields an SBOM with nothing but the archive in it, and nothing else in the
pipeline would notice.

The expectation comes from the lockfile, not from a list kept here:

- cnlman itself and every direct dependency in Cargo.toml must appear, at a
  version Cargo.lock resolves;
- every Rust crate in the SBOM must exist in Cargo.lock at that version.

  sbom_gate.py <sbom.spdx.json> [--root <checkout>]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib


class GateError(Exception):
    """The SBOM does not describe the expected crates."""


def locked(root: pathlib.Path) -> dict[str, set[str]]:
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    versions: dict[str, set[str]] = {}
    for package in lock.get("package", []):
        versions.setdefault(package["name"], set()).add(package["version"])
    return versions


def required(root: pathlib.Path) -> list[str]:
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    names = [manifest["package"]["name"]]
    for key, spec in manifest.get("dependencies", {}).items():
        names.append(spec.get("package", key) if isinstance(spec, dict) else key)
    return names


def crates(sbom: dict) -> dict[str, set[str]]:
    """Rust crates in the SBOM, identified by their cargo purl."""
    found: dict[str, set[str]] = {}
    for package in sbom.get("packages", []):
        purls = [
            ref.get("referenceLocator", "")
            for ref in package.get("externalRefs", [])
            if ref.get("referenceType") == "purl"
        ]
        if any(p.startswith("pkg:cargo/") for p in purls):
            found.setdefault(package["name"], set()).add(package.get("versionInfo", ""))
    return found


def check(sbom: dict, root: pathlib.Path) -> int:
    lock = locked(root)
    present = crates(sbom)
    problems = []
    for name in required(root):
        if not present.get(name, set()) & lock.get(name, set()):
            problems.append(f"missing {name} at a locked version")
    for name, versions in sorted(present.items()):
        if foreign := sorted(versions - lock.get(name, set())):
            problems.append(f"{name} {', '.join(foreign)} is not in Cargo.lock")
    if problems:
        raise GateError("; ".join(problems))
    return sum(len(v) for v in present.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sbom", type=pathlib.Path)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args(argv)
    try:
        count = check(json.loads(args.sbom.read_text(encoding="utf-8")), args.root)
    except (GateError, OSError, ValueError, KeyError) as error:
        print(f"sbom: {args.sbom.name}: {error}", file=sys.stderr)
        return 1
    print(f"sbom: {args.sbom.name}: {count} crates, all locked")
    return 0


if __name__ == "__main__":
    sys.exit(main())

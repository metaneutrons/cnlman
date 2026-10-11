#!/usr/bin/env python3
"""The single list of release assets and the gates built on it.

Every stage of the release pipeline asks this script what it expects instead
of keeping its own list of file names or counts:

  raw          the directory holds exactly the payloads
  payloads     ... and exactly one SBOM and one signature bundle per payload
  definitions  exactly the channel definitions, each with a signature bundle
  write     write SHA256SUMS over exactly the candidate set
  verify    the directory is the candidate set plus SHA256SUMS, and every
            checksum matches
  list      print payload names, one per line
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys

NAME = "cnlman"
UNIX_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
WINDOWS_TARGETS = (
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
)
SUMS = "SHA256SUMS"
# Channel definitions generated from the qualified payloads. They are signed
# and attested but get no SBOM of their own.
DEFINITIONS = ("cnlman.rb",)
TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$")


class InventoryError(Exception):
    """The directory does not match the expected set."""


def payloads(tag: str) -> list[str]:
    if not TAG.match(tag):
        raise InventoryError(f"not a release tag: {tag!r}")
    names = [f"{NAME}-{tag}-{t}.tar.gz" for t in UNIX_TARGETS]
    names += [f"{NAME}-{tag}-{t}.zip" for t in WINDOWS_TARGETS]
    names.append(f"{NAME}-{tag}-source.tar.gz")
    return sorted(names)


def signed_payloads(tag: str) -> list[str]:
    names = []
    for payload in payloads(tag):
        names += [payload, f"{payload}.spdx.json", f"{payload}.sigstore.json"]
    return sorted(names)


def definitions() -> list[str]:
    return sorted(n for d in DEFINITIONS for n in (d, f"{d}.sigstore.json"))


def candidate(tag: str) -> list[str]:
    return sorted(signed_payloads(tag) + definitions())


def present(directory: pathlib.Path) -> set[str]:
    if not directory.is_dir():
        raise InventoryError(f"{directory} is not a directory")
    return {p.name for p in directory.iterdir()}


def require_exact(directory: pathlib.Path, expected: list[str]) -> None:
    have = present(directory)
    want = set(expected)
    problems = []
    if missing := sorted(want - have):
        problems.append("missing: " + ", ".join(missing))
    if extra := sorted(have - want):
        problems.append("unexpected: " + ", ".join(extra))
    for name in sorted(want & have):
        path = directory / name
        if not path.is_file() or path.stat().st_size == 0:
            problems.append(f"empty or not a file: {name}")
    if problems:
        raise InventoryError("; ".join(problems))


def digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sums(directory: pathlib.Path, tag: str) -> None:
    names = candidate(tag)
    require_exact(directory, names)
    lines = [f"{digest(directory / n)}  {n}\n" for n in names]
    (directory / SUMS).write_text("".join(lines), encoding="ascii", newline="\n")


def verify(directory: pathlib.Path, tag: str) -> None:
    names = candidate(tag)
    require_exact(directory, [*names, SUMS])
    listed = {}
    for number, line in enumerate((directory / SUMS).read_text(encoding="ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match:
            raise InventoryError(f"{SUMS} line {number} is malformed")
        if match[2] in listed:
            raise InventoryError(f"{SUMS} lists {match[2]} twice")
        listed[match[2]] = match[1]
    if sorted(listed) != names:
        raise InventoryError(f"{SUMS} does not list exactly the candidate set")
    for name, expected in listed.items():
        if digest(directory / name) != expected:
            raise InventoryError(f"checksum mismatch: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "command", choices=["raw", "payloads", "definitions", "write", "verify", "list"]
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--directory", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            print("\n".join(payloads(args.tag)))
        elif args.command == "raw":
            require_exact(args.directory, payloads(args.tag))
        elif args.command == "payloads":
            require_exact(args.directory, signed_payloads(args.tag))
        elif args.command == "definitions":
            require_exact(args.directory, definitions())
        elif args.command == "write":
            write_sums(args.directory, args.tag)
        else:
            verify(args.directory, args.tag)
    except InventoryError as error:
        print(f"inventory: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

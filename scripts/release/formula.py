#!/usr/bin/env python3
"""Generate the Homebrew formula from the qualified release archives.

The formula names exactly four archives of the given tag, macOS and Linux on
x86_64 and ARM64, each with the SHA-256 of the bytes in the payload
directory. It is generated after signing, so it describes the qualified
bytes, never a rebuild.

  formula.py --tag v1.2.3 --payload-dir payloads --output cnlman.rb
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

import inventory

REPO = "metaneutrons/cnlman"
DESC = "Click'n'Load receiver and decrypter with pyLoad hand-off"
PLATFORMS = (
    # (block, intel?, target)
    ("on_macos", True, "x86_64-apple-darwin"),
    ("on_macos", False, "aarch64-apple-darwin"),
    ("on_linux", True, "x86_64-unknown-linux-gnu"),
    ("on_linux", False, "aarch64-unknown-linux-gnu"),
)
# The same vector as the release smoke test, produced with OpenSSL. The jk
# value is this ASCII text, hex-encoded at test time.
VECTOR_ASCII = "0123456789abcdef"
VECTOR_CRYPTED = (
    "RnATJ+qxAkpHoFYfjZKfGIoMKq9yo6hLgc5BX1Qe/6qUNj/2AN1z0oQMNXP9K7qwLHW2sRDDJb8R3VaX/+cC8Q=="
)


def archive(tag: str, target: str) -> str:
    return f"{inventory.NAME}-{tag}-{target}.tar.gz"


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(tag: str, payload_dir: pathlib.Path) -> str:
    inventory.payloads(tag)  # validates the tag
    base = f"https://github.com/{REPO}/releases/download/{tag}"
    blocks = []
    for block in ("on_macos", "on_linux"):
        rows = {intel: target for b, intel, target in PLATFORMS if b == block}
        lines = [f"  {block} do"]
        for keyword, intel in (("if", True), ("else", False)):
            name = archive(tag, rows[intel])
            path = payload_dir / name
            if not path.is_file():
                raise FileNotFoundError(f"missing payload {name}")
            head = "    if Hardware::CPU.intel?" if keyword == "if" else "    else"
            lines += [head, f'      url "{base}/{name}"', f'      sha256 "{sha256(path)}"']
        lines += ["    end", "  end"]
        blocks.append("\n".join(lines))
    return f'''class Cnlman < Formula
  desc "{DESC}"
  homepage "https://github.com/{REPO}"
  license "GPL-3.0-or-later"

{blocks[0]}

{blocks[1]}

  def install
    bin.install "cnlman"
  end

  test do
    # The binary reports the release core; a prerelease tag carries a suffix.
    assert_equal "cnlman #{{version.major_minor_patch}}", shell_output("#{{bin}}/cnlman --version").strip

    jk = "{VECTOR_ASCII}".unpack1("H*")
    crypted = "{VECTOR_CRYPTED}"
    links = shell_output("#{{bin}}/cnlman decrypt --jk #{{jk}} --crypted #{{crypted}} --format links")
    assert_equal "https://example.org/smoke\\nhttps://example.org/test\\n", links
  end
end
'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--payload-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        text = render(args.tag, args.payload_dir)
    except (inventory.InventoryError, FileNotFoundError) as error:
        print(f"formula: {error}", file=sys.stderr)
        return 1
    args.output.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

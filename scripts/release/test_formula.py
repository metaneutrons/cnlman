"""Probes for the Homebrew formula generator."""

from __future__ import annotations

import hashlib
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

import formula
import inventory

TAG = "v1.2.3"


class Formula(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        for name in inventory.payloads(TAG):
            (self.dir / name).write_bytes(f"bytes of {name}".encode())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_names_exactly_four_archives_of_the_tag_with_their_checksums(self) -> None:
        text = formula.render(TAG, self.dir)
        urls = re.findall(r'url "([^"]+)"', text)
        self.assertEqual(len(urls), 4)
        self.assertEqual(len(set(urls)), 4)
        for url in urls:
            self.assertTrue(url.startswith(f"https://github.com/metaneutrons/cnlman/releases/download/{TAG}/"))
        pairs = re.findall(r'url "[^"]+/([^/"]+)"\n\s+sha256 "([0-9a-f]{64})"', text)
        self.assertEqual(len(pairs), 4)
        for name, digest in pairs:
            self.assertEqual(digest, hashlib.sha256((self.dir / name).read_bytes()).hexdigest())
        self.assertNotIn("windows", text)
        self.assertNotIn("source", text)

    def test_intel_branch_gets_the_x86_64_archive(self) -> None:
        text = formula.render(TAG, self.dir)
        mac = text.split("on_macos do")[1].split("on_linux do")[0]
        intel, arm = mac.split("    else")
        self.assertIn("x86_64-apple-darwin", intel)
        self.assertIn("aarch64-apple-darwin", arm)

    def test_missing_archive_fails(self) -> None:
        (self.dir / f"cnlman-{TAG}-aarch64-unknown-linux-gnu.tar.gz").unlink()
        with self.assertRaises(FileNotFoundError):
            formula.render(TAG, self.dir)

    def test_rejects_a_non_tag(self) -> None:
        with self.assertRaises(inventory.InventoryError):
            formula.render("main", self.dir)

    def test_has_no_explicit_version(self) -> None:
        # Homebrew derives the version from the URL; an explicit one fails
        # `brew audit --strict` as redundant.
        self.assertNotRegex(formula.render(TAG, self.dir), r'^\s*version "')

    @unittest.skipUnless(shutil.which("ruby"), "ruby not installed")
    def test_is_valid_ruby(self) -> None:
        out = self.dir / "cnlman.rb"
        out.write_text(formula.render(TAG, self.dir))
        subprocess.run(["ruby", "-c", str(out)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()

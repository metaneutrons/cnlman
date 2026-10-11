"""Positive probes and counter-probes for the release helpers."""

from __future__ import annotations

import pathlib
import tarfile
import tempfile
import unittest
import zipfile

import inventory
import package

TAG = "v1.2.3"


def fill(directory: pathlib.Path, names) -> None:
    for name in names:
        (directory / name).write_text(f"content of {name}\n")


class Inventory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_payload_list_covers_every_platform_once(self) -> None:
        names = inventory.payloads(TAG)
        self.assertEqual(len(names), 7)
        self.assertEqual(len(set(names)), 7)
        self.assertEqual(sum(n.endswith(".zip") for n in names), 2)
        self.assertIn("cnlman-v1.2.3-source.tar.gz", names)

    def test_rejects_non_tags(self) -> None:
        for bad in ("1.2.3", "v1.2", "v01.2.3", "v1.2.3 ", "main"):
            with self.assertRaises(inventory.InventoryError, msg=bad):
                inventory.payloads(bad)

    def test_round_trip(self) -> None:
        fill(self.dir, inventory.candidate(TAG))
        inventory.write_sums(self.dir, TAG)
        inventory.verify(self.dir, TAG)
        lines = (self.dir / "SHA256SUMS").read_text().splitlines()
        # 7 payloads with SBOM and bundle, plus the formula and its bundle.
        self.assertEqual(len(lines), 23)
        self.assertTrue(any(line.endswith("  cnlman.rb") for line in lines))

    def test_missing_extra_and_empty_files_fail(self) -> None:
        names = inventory.candidate(TAG)
        fill(self.dir, names[1:])
        with self.assertRaisesRegex(inventory.InventoryError, "missing"):
            inventory.write_sums(self.dir, TAG)
        fill(self.dir, [names[0], "stray.txt"])
        with self.assertRaisesRegex(inventory.InventoryError, "unexpected: stray.txt"):
            inventory.write_sums(self.dir, TAG)
        (self.dir / "stray.txt").unlink()
        (self.dir / names[0]).write_text("")
        with self.assertRaisesRegex(inventory.InventoryError, "empty"):
            inventory.write_sums(self.dir, TAG)

    def test_tampered_byte_fails_verification(self) -> None:
        names = inventory.candidate(TAG)
        fill(self.dir, names)
        inventory.write_sums(self.dir, TAG)
        with (self.dir / names[3]).open("ab") as f:
            f.write(b"x")
        with self.assertRaisesRegex(inventory.InventoryError, "checksum mismatch"):
            inventory.verify(self.dir, TAG)

    def test_sums_must_list_exactly_the_candidate_set(self) -> None:
        names = inventory.candidate(TAG)
        fill(self.dir, names)
        inventory.write_sums(self.dir, TAG)
        sums = self.dir / "SHA256SUMS"
        sums.write_text("".join(sums.read_text().splitlines(keepends=True)[1:]))
        with self.assertRaisesRegex(inventory.InventoryError, "exactly"):
            inventory.verify(self.dir, TAG)

    def test_sign_stage_set_excludes_the_definitions(self) -> None:
        fill(self.dir, inventory.signed_payloads(TAG))
        inventory.require_exact(self.dir, inventory.signed_payloads(TAG))
        fill(self.dir, ["cnlman.rb"])
        with self.assertRaisesRegex(inventory.InventoryError, "unexpected: cnlman.rb"):
            inventory.require_exact(self.dir, inventory.signed_payloads(TAG))

    def test_candidate_without_the_formula_bundle_fails(self) -> None:
        names = [n for n in inventory.candidate(TAG) if n != "cnlman.rb.sigstore.json"]
        fill(self.dir, names)
        with self.assertRaisesRegex(inventory.InventoryError, "missing: cnlman.rb.sigstore.json"):
            inventory.write_sums(self.dir, TAG)

    def test_raw_stage_accepts_only_payloads(self) -> None:
        fill(self.dir, inventory.payloads(TAG))
        inventory.require_exact(self.dir, inventory.payloads(TAG))
        fill(self.dir, [inventory.payloads(TAG)[0] + ".spdx.json"])
        with self.assertRaises(inventory.InventoryError):
            inventory.require_exact(self.dir, inventory.payloads(TAG))


class Package(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        (self.dir / "LICENSE").write_text("license\n")
        (self.dir / "README.md").write_text("readme\n")
        (self.dir / "bin").write_bytes(b"\x7fELF binary")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def build(self, target: str, out: str, epoch: int = 1_700_000_000) -> pathlib.Path:
        package.main([
            "--tag", TAG, "--target", target, "--binary", str(self.dir / "bin"),
            "--root", str(self.dir), "--output-dir", str(self.dir / out),
            "--source-date-epoch", str(epoch),
        ])
        suffix = ".zip" if "windows" in target else ".tar.gz"
        return self.dir / out / f"cnlman-{TAG}-{target}{suffix}"

    def test_tar_is_reproducible_and_normalised(self) -> None:
        first = self.build("x86_64-unknown-linux-gnu", "a")
        second = self.build("x86_64-unknown-linux-gnu", "b")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as tar:
            members = {m.name: m for m in tar.getmembers()}
        prefix = f"cnlman-{TAG}-x86_64-unknown-linux-gnu"
        self.assertEqual(sorted(members), [prefix, f"{prefix}/LICENSE", f"{prefix}/README.md", f"{prefix}/cnlman"])
        self.assertEqual(members[f"{prefix}/cnlman"].mode, 0o755)
        self.assertEqual(members[f"{prefix}/cnlman"].mtime, 1_700_000_000)

    def test_other_epoch_changes_the_bytes(self) -> None:
        first = self.build("x86_64-unknown-linux-gnu", "a")
        other = self.build("x86_64-unknown-linux-gnu", "b", epoch=1_700_000_001)
        self.assertNotEqual(first.read_bytes(), other.read_bytes())

    def test_zip_carries_the_exe(self) -> None:
        first = self.build("aarch64-pc-windows-msvc", "a")
        second = self.build("aarch64-pc-windows-msvc", "b")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as z:
            self.assertIn(f"cnlman-{TAG}-aarch64-pc-windows-msvc/cnlman.exe", z.namelist())


if __name__ == "__main__":
    unittest.main()

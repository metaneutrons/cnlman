"""Positive probes and counter-probes for the SBOM gate."""

from __future__ import annotations

import pathlib
import tempfile
import unittest

import sbom_gate

MANIFEST = """
[package]
name = "demo"
version = "1.0.0"

[dependencies]
alpha = "1"
renamed = { package = "beta", version = "2" }
"""

LOCK = """
version = 4

[[package]]
name = "demo"
version = "1.0.0"

[[package]]
name = "alpha"
version = "1.2.0"

[[package]]
name = "beta"
version = "2.0.1"

[[package]]
name = "gamma"
version = "0.3.0"
"""


def crate(name: str, version: str) -> dict:
    return {
        "name": name,
        "versionInfo": version,
        "externalRefs": [
            {"referenceType": "purl", "referenceLocator": f"pkg:cargo/{name}@{version}"}
        ],
    }


ARCHIVE = {"name": "demo.tar.gz", "versionInfo": "", "externalRefs": []}


class Gate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        (self.root / "Cargo.toml").write_text(MANIFEST)
        (self.root / "Cargo.lock").write_text(LOCK)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def sbom(self, *packages: dict) -> dict:
        return {"spdxVersion": "SPDX-2.3", "packages": [ARCHIVE, *packages]}

    def test_complete_graph_passes(self) -> None:
        sbom = self.sbom(
            crate("demo", "1.0.0"), crate("alpha", "1.2.0"),
            crate("beta", "2.0.1"), crate("gamma", "0.3.0"),
        )
        self.assertEqual(sbom_gate.check(sbom, self.root), 4)

    def test_archive_only_sbom_fails(self) -> None:
        with self.assertRaisesRegex(sbom_gate.GateError, "missing demo"):
            sbom_gate.check(self.sbom(), self.root)

    def test_renamed_dependency_is_checked_under_its_package_name(self) -> None:
        sbom = self.sbom(crate("demo", "1.0.0"), crate("alpha", "1.2.0"))
        with self.assertRaisesRegex(sbom_gate.GateError, "missing beta"):
            sbom_gate.check(sbom, self.root)

    def test_wrong_version_fails(self) -> None:
        sbom = self.sbom(
            crate("demo", "1.0.0"), crate("alpha", "1.1.0"), crate("beta", "2.0.1"),
        )
        with self.assertRaisesRegex(sbom_gate.GateError, "alpha 1.1.0 is not in Cargo.lock"):
            sbom_gate.check(sbom, self.root)

    def test_crate_outside_the_lockfile_fails(self) -> None:
        sbom = self.sbom(
            crate("demo", "1.0.0"), crate("alpha", "1.2.0"),
            crate("beta", "2.0.1"), crate("intruder", "9.9.9"),
        )
        with self.assertRaisesRegex(sbom_gate.GateError, "intruder"):
            sbom_gate.check(sbom, self.root)

    def test_non_cargo_packages_are_ignored(self) -> None:
        other = {"name": "alpha", "versionInfo": "0.0.1",
                 "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/alpha@0.0.1"}]}
        sbom = self.sbom(
            crate("demo", "1.0.0"), crate("alpha", "1.2.0"), crate("beta", "2.0.1"), other,
        )
        self.assertEqual(sbom_gate.check(sbom, self.root), 3)



class PinnedVersion(unittest.TestCase):
    """CI qualifies the same cargo-auditable that the release uses."""

    def test_ci_and_release_pin_the_same_version(self) -> None:
        import re

        workflows = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
        pins = {}
        for name in ("ci.yml", "release.yml"):
            found = re.findall(r"CARGO_AUDITABLE_VERSION: '([^']+)'", (workflows / name).read_text())
            self.assertEqual(len(found), 1, f"{name} must pin cargo-auditable exactly once")
            pins[name] = found[0]
        self.assertEqual(pins["ci.yml"], pins["release.yml"])


if __name__ == "__main__":
    unittest.main()

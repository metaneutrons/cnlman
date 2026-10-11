#!/usr/bin/env python3
"""Build one release archive reproducibly.

The archive holds a single top-level directory named after the archive,
containing the binary, LICENSE and README.md. Timestamps come from
SOURCE_DATE_EPOCH, owners are root, permissions are normalised and entries are
sorted, so the same inputs give the same bytes on every runner.
"""

from __future__ import annotations

import argparse
import gzip
import io
import pathlib
import sys
import tarfile
import time
import zipfile

NAME = "cnlman"
DOCS = ("LICENSE", "README.md")


def entries(binary: pathlib.Path, root: pathlib.Path, windows: bool) -> list[tuple[str, bytes, int]]:
    exe = f"{NAME}.exe" if windows else NAME
    items = [(exe, binary.read_bytes(), 0o755)]
    items += [(doc, (root / doc).read_bytes(), 0o644) for doc in DOCS]
    return sorted(items)


def write_tar_gz(out: pathlib.Path, prefix: str, items, epoch: int) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        directory = tarfile.TarInfo(prefix)
        directory.type, directory.mode, directory.mtime = tarfile.DIRTYPE, 0o755, epoch
        tar.addfile(directory)
        for name, data, mode in items:
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size, info.mode, info.mtime = len(data), mode, epoch
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    with out.open("wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=epoch, compresslevel=9) as gz:
        gz.write(raw.getvalue())


def write_zip(out: pathlib.Path, prefix: str, items, epoch: int) -> None:
    stamp = time.gmtime(max(epoch, 315532800))[:6]  # ZIP cannot date before 1980
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data, mode in items:
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=stamp)
            info.external_attr = (0o100000 | mode) << 16
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    args = parser.parse_args(argv)

    windows = "windows" in args.target
    prefix = f"{NAME}-{args.tag}-{args.target}"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    items = entries(args.binary, args.root, windows)
    if windows:
        out = args.output_dir / f"{prefix}.zip"
        write_zip(out, prefix, items, args.source_date_epoch)
    else:
        out = args.output_dir / f"{prefix}.tar.gz"
        write_tar_gz(out, prefix, items, args.source_date_epoch)
    print(out.as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Package the cross-compiled ktunnel binaries as platform-specific wheels.

This is the same trick ruff and uv use: a wheel is just a zip, and anything
placed in ``<name>-<version>.data/scripts/`` is dropped straight onto PATH at
install time. No Python wrapper process sits in front of the binary — the
wheel is only a delivery vehicle.

Usage:
    python3 packaging/build_wheels.py 0.2.0
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import sys
import zipfile
from pathlib import Path

NAME = "ktunnel"
ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
OUT = DIST / "wheels"

# Go target -> (wheel platform tag, binary suffix)
TARGETS = {
    "darwin-arm64":  ("macosx_11_0_arm64", ""),
    "darwin-amd64":  ("macosx_10_12_x86_64", ""),
    "linux-amd64":   ("manylinux2014_x86_64.manylinux_2_17_x86_64", ""),
    "linux-arm64":   ("manylinux2014_aarch64.manylinux_2_17_aarch64", ""),
    "windows-amd64": ("win_amd64", ".exe"),
}

SUMMARY = "Expose a local port at https://<name>.<domain> through a self-hosted frp relay"


def metadata(version: str) -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {NAME}\n"
        f"Version: {version}\n"
        f"Summary: {SUMMARY}\n"
        "License: MIT\n"
        "Requires-Python: >=3.8\n"
        "Description-Content-Type: text/markdown\n"
        "\n" + readme
    )


def wheel_metadata(tag: str) -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: ktunnel-build-wheels\n"
        "Root-Is-Purelib: false\n"
        f"Tag: {tag}\n"
    )


def urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build(version: str, target: str, plat: str, suffix: str) -> Path:
    binary = DIST / f"{NAME}-{target}{suffix}"
    if not binary.exists():
        raise SystemExit(f"missing binary: {binary} — run ./build.sh first")

    tag = f"py3-none-{plat}"
    OUT.mkdir(parents=True, exist_ok=True)
    wheel_path = OUT / f"{NAME}-{version}-{tag}.whl"

    distinfo = f"{NAME}-{version}.dist-info"
    datadir = f"{NAME}-{version}.data/scripts"
    records: list[tuple[str, str, int]] = []

    def add(zf: zipfile.ZipFile, arcname: str, payload: bytes, *, executable: bool = False) -> None:
        info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
        # 0o755 for the binary so it stays executable through the zip round trip
        info.external_attr = ((0o755 if executable else 0o644) << 16) | 0o600
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, payload)
        digest = urlsafe_b64(hashlib.sha256(payload).digest())
        records.append((arcname, f"sha256={digest}", len(payload)))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        add(zf, f"{datadir}/{NAME}{suffix}", binary.read_bytes(), executable=True)
        add(zf, f"{distinfo}/METADATA", metadata(version).encode("utf-8"))
        add(zf, f"{distinfo}/WHEEL", wheel_metadata(tag).encode("utf-8"))
        add(zf, f"{distinfo}/licenses/LICENSE", (ROOT / "LICENSE").read_bytes())

        record_io = io.StringIO()
        writer = csv.writer(record_io, lineterminator="\n")
        for row in records:
            writer.writerow(row)
        writer.writerow([f"{distinfo}/RECORD", "", ""])
        info = zipfile.ZipInfo(f"{distinfo}/RECORD", date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = (0o644 << 16) | 0o600
        zf.writestr(info, record_io.getvalue())

    wheel_path.write_bytes(buf.getvalue())
    return wheel_path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_wheels.py <version>   (e.g. 0.2.0)")
    version = sys.argv[1].lstrip("v")
    for target, (plat, suffix) in TARGETS.items():
        path = build(version, target, plat, suffix)
        print(f"  {path.name}  ({path.stat().st_size / 1048576:.1f} MB)")


if __name__ == "__main__":
    main()

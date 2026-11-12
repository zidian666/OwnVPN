"""Build and verify a source-only macOS migration handoff (Python stdlib).

Only explicit project roots are read. Never reads AppData, Credential Manager,
mail attachments, desktop screenshots, build binaries or runtime VPN profiles.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile


ROOT_FILES = (
    ".clang-format", ".gitignore", ".gitattributes", "CMakeLists.txt", "build.ps1", "README.md",
    "THIRD_PARTY_NOTICES.txt", "START_HERE_MAC.md",
)
SOURCE_ROOTS = ("src", "cmake", "docs", "resources", "tests", "tools")
TEXT_SUFFIXES = {".cpp", ".h", ".cmake", ".md", ".txt", ".py", ".ps1", ".rc", ".manifest", ".specs", ".svg"}
PUBLIC_IMAGES = {
    "resources/app.ico", "resources/app-icon.png", "resources/app-connected.ico", "resources/app-icon-connected.png",
    "tests/fixtures/totp-standard.png", "tests/fixtures/totp-rotated.png",
    "tests/fixtures/not-totp.png", "tests/fixtures/multiple-qr.png", "tests/fixtures/blank.png",
}
FORBIDDEN = {".pem", ".key", ".crt", ".ovpn", ".p12", ".pfx", ".p8", ".der", ".log", ".exe", ".dll", ".zip", ".db", ".sqlite"}
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect(root: Path) -> dict[str, bytes]:
    paths = [root / name for name in ROOT_FILES]
    for directory in SOURCE_ROOTS:
        paths.extend(path for path in (root / directory).rglob("*") if path.is_file())
    result = {}
    for path in sorted(paths):
        if "__pycache__" in path.parts or path.suffix.lower() in {".pyc", ".pyo"}:
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(f"Refusing external link: {relative}")
        if any(part.startswith(".") for part in path.relative_to(root).parts) and relative not in ROOT_FILES:
            raise ValueError(f"Unreviewed hidden file: {relative}")
        if path.suffix.lower() in FORBIDDEN:
            raise ValueError(f"Runtime/private file is not allowed: {relative}")
        if relative not in ROOT_FILES and path.suffix.lower() not in TEXT_SUFFIXES and relative not in PUBLIC_IMAGES:
            raise ValueError(f"Unreviewed source asset: {relative}")
        data = path.read_bytes()
        if PRIVATE_KEY.search(data):
            raise ValueError(f"Private-key material detected: {relative}")
        result[relative] = data
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", default=datetime.now().strftime("%Y%m%d"))
    args = parser.parse_args()
    if not re.fullmatch(r"\d{8}", args.date):
        parser.error("--date must be YYYYMMDD")
    root = Path(__file__).resolve().parents[1]
    payload = collect(root)
    version = re.search(r"project\(OwnVPN VERSION ([\d.]+)", payload["CMakeLists.txt"].decode()).group(1)
    cmake = payload["cmake/ZXing.cmake"].decode()
    dependency_version = re.search(r"set\(ZXING_VERSION ([\d.]+)\)", cmake).group(1)
    dependency_sha = re.search(r"set\(ZXING_SHA256 ([0-9a-f]{64})\)", cmake).group(1)
    archive_name = f"ZXing-Cpp-{dependency_version}-source.tar.gz"
    dependency = root / "build" / "downloads" / f"zxing-cpp-{dependency_version}.tar.gz"
    if not dependency.is_file():
        dependency = root / "third_party" / archive_name
    dependency_bytes = dependency.read_bytes()
    if digest(dependency_bytes) != dependency_sha:
        raise ValueError("Pinned ZXing dependency checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(dependency_bytes), mode="r:gz") as source:
        license_entry = source.extractfile(f"zxing-cpp-{dependency_version}/LICENSE")
        if license_entry is None:
            raise ValueError("ZXing license is missing")
        license_bytes = license_entry.read()
    payload[f"third_party/{archive_name}"] = dependency_bytes
    payload["third_party/LICENSE-ZXing.txt"] = license_bytes
    manifest = {
        "project": "OwnVPN", "source_version": version,
        "purpose": "Windows source baseline for macOS migration; not a macOS executable",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "excluded": ["build/dist binaries and caches", "AppData", "Credential Manager",
                     "real VPN profiles, certificates and private keys", "personal QR images, TOTP seeds and passwords", "runtime logs"],
        "file_count_excluding_manifest": len(payload),
        "files": [{"path": name, "bytes": len(data), "sha256": digest(data)}
                  for name, data in sorted(payload.items())],
    }
    payload["PACKAGE_MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    folder = f"OwnVPN-{version}-mac-migration"
    destination = root / "packages"
    destination.mkdir(exist_ok=True)
    archive = destination / f"{folder}-{args.date}.zip"
    if archive.exists():
        raise FileExistsError(f"Refusing to overwrite an existing handoff: {archive.name}")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(f"{folder}/{name}")
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            output.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    # Verify the produced ZIP, safe member names and every payload hash.
    with zipfile.ZipFile(archive) as output:
        if output.testzip() is not None:
            raise ValueError("Archive CRC validation failed")
        if len(output.namelist()) != len(payload):
            raise ValueError("Archive entry count mismatch")
        for name, data in payload.items():
            member = f"{folder}/{name}"
            if PurePosixPath(member).is_absolute() or ".." in PurePosixPath(member).parts:
                raise ValueError("Unsafe archive member path")
            if digest(output.read(member)) != digest(data):
                raise ValueError(f"Archive hash mismatch: {name}")
    archive_sha = digest(archive.read_bytes())
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(f"{archive_sha}  {archive.name}\n", encoding="ascii")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size,
                      "entries": len(payload), "sha256": archive_sha,
                      "checksum": str(checksum), "verified": True}, indent=2))


if __name__ == "__main__":
    main()

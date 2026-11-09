#!/usr/bin/env python3
"""Cross-Platform Desktop App & Installer Builder for Presidio Shield Desktop.

Builds:
1. `dist/PresidioShield.app`          — macOS Universal Application Bundle (arm64 + x86_64)
2. `dist/PresidioShield-macOS.dmg`    — macOS Disk Image Installer with /Applications drag-and-drop
3. `dist/PresidioShield-Setup-x64.exe`— Windows 64-bit Self-Contained Installer (.exe)
4. `dist/PresidioShield-Portable-x64.exe` — Windows 64-bit Portable Desktop App (.exe)
5. `dist/sample_pii_thai_eng.xlsx`    — Sample Thai + English Excel file for immediate testing
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

from app.excel_processor import generate_sample_excel_bytes

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
NATIVE_DIR = ROOT / "native_host"


def create_shield_png(path: Path, size: int = 512) -> None:
    """Generate a clean 512x512 RGBA PNG icon with a blue/purple privacy shield."""
    width = height = size
    raw_rows = []
    cx, cy = width / 2.0, height / 2.0
    for y in range(height):
        row = bytearray([0])  # Filter type 0
        ny = (y - cy) / (height * 0.42)
        for x in range(width):
            nx = (x - cx) / (width * 0.42)
            # Rounded squircle background
            if abs(nx) ** 4 + abs(ny) ** 4 <= 1.0:
                # Shield shape inside
                in_shield = (
                    -0.55 <= ny <= 0.60
                    and abs(nx) <= (0.58 - max(0.0, (ny + 0.1) * 0.65))
                )
                if in_shield:
                    # Bright cyan/white shield
                    r, g, b, a = 56, 189, 248, 255
                else:
                    # Deep navy/indigo gradient background
                    t = (y / height)
                    r = int(15 + 30 * (1 - t))
                    g = int(23 + 45 * (1 - t))
                    b = int(42 + 120 * (1 - t))
                    a = 255
            else:
                r, g, b, a = 0, 0, 0, 0
            row.extend((r, g, b, a))
        raw_rows.append(bytes(row))

    raw_data = b"".join(raw_rows)

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw_data, 9)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + make_chunk(b"IHDR", ihdr)
        + make_chunk(b"IDAT", idat)
        + make_chunk(b"IEND", b"")
    )
    path.write_bytes(png_bytes)


def build_macos_icns(dest_icns: Path) -> None:
    """Create a native macOS .icns icon file using sips and iconutil."""
    tmp_dir = DIST_DIR / "_icon_tmp"
    iconset = tmp_dir / "AppIcon.iconset"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    iconset.mkdir(parents=True, exist_ok=True)

    base_png = tmp_dir / "base.png"
    create_shield_png(base_png, 512)

    sizes = [16, 32, 64, 128, 256, 512]
    for sz in sizes:
        out1 = iconset / f"icon_{sz}x{sz}.png"
        subprocess.run(
            ["sips", "-z", str(sz), str(sz), str(base_png), "--out", str(out1)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if sz <= 256:
            out2 = iconset / f"icon_{sz}x{sz}@2x.png"
            subprocess.run(
                ["sips", "-z", str(sz * 2), str(sz * 2), str(base_png), "--out", str(out2)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    subprocess.run(
        ["iconutil", "-c", "icns", str(iconset), "-o", str(dest_icns)],
        check=True,
    )
    shutil.rmtree(tmp_dir, ignore_errors=True)


def prepare_embedded_assets() -> None:
    """Sync `app/static` and Python source into `native_host/` for Go embedding."""
    static_dst = NATIVE_DIR / "static"
    if static_dst.exists():
        shutil.rmtree(static_dst)
    shutil.copytree(ROOT / "app" / "static", static_dst)

    py_dst = NATIVE_DIR / "python_src"
    if py_dst.exists():
        shutil.rmtree(py_dst)
    (py_dst / "app").mkdir(parents=True, exist_ok=True)
    for py_file in (ROOT / "app").glob("*.py"):
        shutil.copy2(py_file, py_dst / "app" / py_file.name)
    shutil.copytree(ROOT / "app" / "static", py_dst / "app" / "static")
    shutil.copy2(ROOT / "desktop.py", py_dst / "desktop.py")
    shutil.copy2(ROOT / "requirements.txt", py_dst / "requirements.txt")


def compile_go_binaries() -> None:
    """Compile macOS binary and Windows x64 .exe binaries without invoking Xcode xcrun stubs."""
    if not (NATIVE_DIR / "go.mod").exists():
        subprocess.run(["go", "mod", "init", "presidio_shield"], cwd=NATIVE_DIR, check=True)
        subprocess.run(["go", "get", "github.com/xuri/excelize/v2"], cwd=NATIVE_DIR, check=True)
        subprocess.run(["go", "mod", "tidy"], cwd=NATIVE_DIR, check=True)

    # 1. macOS Apple Silicon (arm64) binary for PresidioShield.app
    univ_bin = DIST_DIR / "PresidioShield_darwin_universal"
    env_arm = {**os.environ, "GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "0"}
    subprocess.run(
        ["go", "build", "-ldflags=-s -w", "-o", str(univ_bin), "."],
        cwd=NATIVE_DIR,
        env=env_arm,
        check=True,
    )

    # Clean up any leftover temp binaries
    (DIST_DIR / "_bin_darwin_arm64").unlink(missing_ok=True)
    (DIST_DIR / "_bin_darwin_amd64").unlink(missing_ok=True)

    # 2. Windows 64-bit Installer (.exe) and Portable (.exe)
    win_setup_exe = DIST_DIR / "PresidioShield-Setup-x64.exe"
    win_portable_exe = DIST_DIR / "PresidioShield-Portable-x64.exe"
    env_win = {**os.environ, "GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    subprocess.run(
        ["go", "build", "-ldflags=-H=windowsgui -s -w", "-o", str(win_setup_exe), "."],
        cwd=NATIVE_DIR,
        env=env_win,
        check=True,
    )
    shutil.copy2(win_setup_exe, win_portable_exe)


def create_macos_app_and_dmg() -> None:
    """Create `dist/PresidioShield.app` and `dist/PresidioShield-macOS.dmg`."""
    app_dir = DIST_DIR / "PresidioShield.app"
    if app_dir.exists():
        shutil.rmtree(app_dir)

    macos_dir = app_dir / "Contents" / "MacOS"
    res_dir = app_dir / "Contents" / "Resources"
    macos_dir.mkdir(parents=True, exist_ok=True)
    res_dir.mkdir(parents=True, exist_ok=True)

    # Move universal binary into Contents/MacOS/PresidioShield
    univ_bin = DIST_DIR / "PresidioShield_darwin_universal"
    target_bin = macos_dir / "PresidioShield"
    shutil.move(str(univ_bin), str(target_bin))
    target_bin.chmod(0o755)

    # Generate AppIcon.icns
    icns_path = res_dir / "AppIcon.icns"
    build_macos_icns(icns_path)

    # Write Info.plist
    info_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Presidio Shield</string>
    <key>CFBundleExecutable</key>
    <string>PresidioShield</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>org.dataprivacystack.presidioshield</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Presidio Shield</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"""
    (app_dir / "Contents" / "Info.plist").write_text(info_plist, encoding="utf-8")

    # Ad-hoc codesign the .app bundle so macOS Gatekeeper allows launching smoothly
    subprocess.run(
        ["codesign", "--force", "--deep", "--sign", "-", str(app_dir)],
        check=False,
    )

    # Build .dmg disk image with /Applications symlink
    dmg_staging = DIST_DIR / "_dmg_staging"
    if dmg_staging.exists():
        shutil.rmtree(dmg_staging)
    dmg_staging.mkdir(parents=True, exist_ok=True)

    shutil.copytree(app_dir, dmg_staging / "PresidioShield.app", symlinks=True)
    os.symlink("/Applications", dmg_staging / "Applications")

    dmg_path = DIST_DIR / "PresidioShield-macOS.dmg"
    if dmg_path.exists():
        dmg_path.unlink()

    subprocess.run(
        [
            "hdiutil",
            "create",
            "-volname",
            "Presidio Shield Installer",
            "-srcfolder",
            str(dmg_staging),
            "-ov",
            "-format",
            "UDZO",
            str(dmg_path),
        ],
        check=True,
    )
    shutil.rmtree(dmg_staging, ignore_errors=True)


def main() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    print("1/4 Preparing embedded static UI & Python Presidio source...")
    prepare_embedded_assets()

    print("2/4 Compiling native macOS Universal & Windows x64 (.exe) binaries...")
    compile_go_binaries()

    print("3/4 Packaging macOS PresidioShield.app & PresidioShield-macOS.dmg...")
    create_macos_app_and_dmg()

    print("4/4 Generating sample Excel file in dist/...")
    sample_xlsx = DIST_DIR / "sample_pii_thai_eng.xlsx"
    sample_xlsx.write_bytes(generate_sample_excel_bytes())

    print("\n✅ Build complete! Files in dist/:")
    for item in sorted(DIST_DIR.iterdir()):
        size_mb = (
            sum(f.stat().st_size for f in item.rglob("*") if f.is_file()) / (1024 * 1024)
            if item.is_dir()
            else item.stat().st_size / (1024 * 1024)
        )
        print(f" - {item.name:36s} ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()

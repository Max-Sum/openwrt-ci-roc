#!/usr/bin/env python3
import argparse
import os
import re
import sys
from pathlib import Path


SEARCH_DIRS = ("package", "feeds", "target/linux")


def package_block_name(package: str) -> tuple[str, str]:
    if package.startswith("kmod-"):
        return "KernelPackage", package.removeprefix("kmod-")
    return "Package", package


def read_packages(path: Path) -> list[str]:
    packages: list[str] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        package = raw_line.strip()
        if not package or package.startswith("#"):
            continue
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$", package):
            print(f"warning: ignored invalid package name: {package}", file=sys.stderr)
            continue
        if package not in seen:
            seen.add(package)
            packages.append(package)
    return packages


def candidate_files(openwrt_root: Path) -> list[Path]:
    files: list[Path] = []
    for name in SEARCH_DIRS:
        root = openwrt_root / name
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [item for item in dirnames if item not in {".git", "build_dir", "bin", "tmp"}]
            for filename in filenames:
                if filename == "Makefile" or filename.endswith(".mk"):
                    files.append(Path(dirpath) / filename)
    return files


def patch_file(path: Path, wanted: dict[tuple[str, str], str], target: str) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    matched: set[str] = set()
    changed = False
    index = 0

    while index < len(lines):
        line = lines[index].strip()
        if not line.startswith("define "):
            index += 1
            continue

        parts = line.split(None, 1)
        if len(parts) != 2 or "/" not in parts[1]:
            index += 1
            continue
        kind, name = parts[1].split("/", 1)
        package = wanted.get((kind, name))
        if not package:
            index += 1
            continue

        end = index + 1
        while end < len(lines) and lines[end].strip() != "endef":
            end += 1
        if end >= len(lines):
            index += 1
            continue

        matched.add(package)
        if not any(f"@!{target}" in item for item in lines[index : end + 1]):
            lines.insert(end, f"  DEPENDS += @!{target}")
            changed = True
            index = end + 2
        else:
            index = end + 1

    if changed:
        ending = "\n" if text.endswith("\n") else ""
        path.write_text("\n".join(lines) + ending, encoding="utf-8")
    return matched


def exclude_packages(openwrt_root: Path, packages: list[str], target: str) -> tuple[int, int]:
    files = candidate_files(openwrt_root)
    wanted = {package_block_name(package): package for package in packages}
    matched: set[str] = set()

    for path in files:
        try:
            matched.update(patch_file(path, wanted, target))
        except UnicodeDecodeError:
            continue

    missing = 0
    for package in packages:
        if package not in matched:
            missing += 1
            print(f"warning: package definition not found: {package}", file=sys.stderr)

    return len(matched), missing


def main() -> None:
    parser = argparse.ArgumentParser(description="Make selected OpenWrt packages unavailable for one target.")
    parser.add_argument("--openwrt-root", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("excluded_packages", type=Path)
    args = parser.parse_args()

    packages = read_packages(args.excluded_packages)
    patched_or_present, missing = exclude_packages(args.openwrt_root, packages, args.target)
    print(f"excluded package rules present: {patched_or_present}")
    print(f"missing package definitions: {missing}")


if __name__ == "__main__":
    main()

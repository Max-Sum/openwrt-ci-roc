#!/usr/bin/env python3
import argparse
import dataclasses
import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zlib
from pathlib import Path


DEFAULT_PACKAGE_ADB_URLS = [
    "https://mirrors.vsean.net/openwrt/snapshots/targets/qualcommax/ipq60xx/packages/packages.adb",
    "https://mirrors.vsean.net/openwrt/snapshots/packages/aarch64_cortex-a53/base/packages.adb",
    "https://mirrors.vsean.net/openwrt/snapshots/packages/aarch64_cortex-a53/luci/packages.adb",
    "https://mirrors.vsean.net/openwrt/snapshots/packages/aarch64_cortex-a53/packages/packages.adb",
    "https://mirrors.vsean.net/openwrt/snapshots/packages/aarch64_cortex-a53/routing/packages.adb",
    "https://mirrors.vsean.net/openwrt/snapshots/packages/aarch64_cortex-a53/telephony/packages.adb",
]

PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")
CONFIG_PACKAGE_RE = re.compile(r"^CONFIG_PACKAGE_([^=]+)=(y|m)$")
DISABLED_CONFIG_PACKAGE_RE = re.compile(r"^# CONFIG_PACKAGE_([^ ]+) is not set$")
DISABLED_CONFIG_PACKAGE_VALUE_RE = re.compile(r"^CONFIG_PACKAGE_([^=]+)=n$")


@dataclasses.dataclass
class PackageInfo:
    name: str
    provides: list[str] = dataclasses.field(default_factory=list)


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def canon(name: str) -> str:
    return re.sub(r"[-.+]", "_", name)


def split_dep_tokens(value: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        if depth == 0 and ch in {",", " ", "\t", "\n"}:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def dep_name_from_token(token: str) -> str | None:
    token = token.strip().strip(",").lstrip("+")
    if not token or token.startswith("@") or token.startswith("("):
        return None
    if ":" in token:
        token = token.rsplit(":", 1)[1]
    if token.startswith("@") or token.startswith("("):
        return None
    return token if PACKAGE_RE.match(token) else None


def parse_provides(value: str) -> list[str]:
    names: list[str] = []
    for token in split_dep_tokens(value.replace("\n", " ")):
        name = dep_name_from_token(token)
        if name and not name.endswith("-any"):
            names.append(name)
    return names


def add_package_info(package_map: dict[str, PackageInfo], info: PackageInfo) -> None:
    for alias in [info.name] + info.provides:
        if alias:
            package_map.setdefault(canon(alias), info)


def parse_control_records(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    current_key: str | None = None

    def flush() -> None:
        nonlocal fields, current_key
        if fields:
            records.append(fields)
        fields = {}
        current_key = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line == "@@" or not line.strip():
            flush()
            continue
        if line[0].isspace() and current_key:
            fields[current_key] += "\n" + line.strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
        current_key = key.strip()
    flush()
    return records


def parse_text_package_index(path: Path) -> dict[str, PackageInfo]:
    package_map: dict[str, PackageInfo] = {}
    for fields in parse_control_records(path.read_text(encoding="utf-8", errors="replace")):
        name = fields.get("Package") or fields.get("P") or fields.get("name")
        if not name or not PACKAGE_RE.match(name):
            continue
        info = PackageInfo(
            name=name,
            provides=parse_provides(fields.get("Provides") or fields.get("provides") or ""),
        )
        add_package_info(package_map, info)
    return package_map


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def adb_offset(value: int) -> int:
    return value & 0x0FFFFFFF


def adb_blob(adb: bytes, value: int) -> str | None:
    if not value:
        return None
    value_type = value & 0xF0000000
    offset = adb_offset(value)
    if offset >= len(adb):
        return None
    if value_type == 0x80000000:
        length = adb[offset]
        start = offset + 1
    elif value_type == 0x90000000:
        length = struct.unpack_from("<H", adb, offset)[0]
        start = offset + 2
    elif value_type == 0xA0000000:
        length = u32(adb, offset)
        start = offset + 4
    else:
        return None
    if start + length > len(adb):
        return None
    return adb[start : start + length].decode("utf-8", errors="replace")


def adb_obj_values(adb: bytes, value: int) -> list[int]:
    offset = adb_offset(value)
    if offset + 4 > len(adb):
        return []
    count = u32(adb, offset)
    if count < 1 or count > 100000 or offset + count * 4 > len(adb):
        return []
    return list(struct.unpack_from("<" + "I" * count, adb, offset))


def inflate_adb(data: bytes) -> bytes:
    if data.startswith(b"ADBd"):
        return zlib.decompress(data[4:], -15)
    if data.startswith(b"ADBc"):
        if len(data) < 6:
            die("ADBc header is truncated")
        if data[4] != 1:
            die(f"unsupported ADBc compression algorithm {data[4]}")
        return zlib.decompress(data[6:], -15)
    return data


def adb_payloads(data: bytes) -> list[bytes]:
    adb_file = inflate_adb(data)
    if not adb_file.startswith(b"ADB."):
        return []
    payloads: list[bytes] = []
    pos = 8
    while pos + 4 <= len(adb_file):
        type_size = u32(adb_file, pos)
        block_type = type_size >> 30
        header_size = 4
        raw_size = type_size & 0x3FFFFFFF
        if block_type == 3:
            block_type = type_size & 0x3FFFFFFF
            header_size = 16
            raw_size = struct.unpack_from("<Q", adb_file, pos + 8)[0]
        if raw_size == 0:
            break
        if raw_size < header_size or pos + raw_size > len(adb_file):
            die("invalid ADB block size")
        if block_type == 0:
            payloads.append(adb_file[pos + header_size : pos + raw_size])
        pos += ((raw_size + 7) // 8) * 8
    return payloads


def parse_adb_provides(adb: bytes, value: int) -> list[str]:
    provides: list[str] = []
    if not value:
        return provides
    for provide_value in adb_obj_values(adb, value)[1:]:
        values = adb_obj_values(adb, provide_value)
        if len(values) < 2:
            continue
        name = adb_blob(adb, values[1])
        if name and PACKAGE_RE.match(name) and not name.endswith("-any"):
            provides.append(name)
    return provides


def parse_adb_package_index(path: Path) -> dict[str, PackageInfo]:
    package_map: dict[str, PackageInfo] = {}
    for payload in adb_payloads(path.read_bytes()):
        if len(payload) < 8:
            continue
        root = adb_obj_values(payload, u32(payload, 4))
        if len(root) < 3:
            continue
        for package_value in adb_obj_values(payload, root[2])[1:]:
            values = adb_obj_values(payload, package_value)
            if len(values) < 3:
                continue
            name = adb_blob(payload, values[1])
            if not name or not PACKAGE_RE.match(name):
                continue
            provides = parse_adb_provides(payload, values[16]) if len(values) > 16 else []
            add_package_info(package_map, PackageInfo(name=name, provides=provides))
    return package_map


def parse_package_index(path: Path) -> dict[str, PackageInfo]:
    data = path.read_bytes()
    if data.startswith((b"ADBd", b"ADBc", b"ADB.")):
        return parse_adb_package_index(path)
    return parse_text_package_index(path)


def merge_package_maps(package_maps: list[dict[str, PackageInfo]]) -> dict[str, PackageInfo]:
    merged: dict[str, PackageInfo] = {}
    for package_map in package_maps:
        merged.update(package_map)
    return merged


def selected_packages_from_config(config_text: str) -> dict[str, str]:
    selected: dict[str, str] = {}
    for line in config_text.splitlines():
        match = CONFIG_PACKAGE_RE.match(line.strip())
        if match:
            selected[canon(match.group(1))] = match.group(1)
    return selected


def disabled_packages_from_config(config_text: str) -> set[str]:
    disabled: set[str] = set()
    for line in config_text.splitlines():
        stripped = line.strip()
        match = DISABLED_CONFIG_PACKAGE_RE.match(stripped) or DISABLED_CONFIG_PACKAGE_VALUE_RE.match(stripped)
        if match:
            disabled.add(canon(match.group(1)))
    return disabled


def render_missing_packages(missing: list[str]) -> str:
    return "".join(f"{name}\n" for name in sorted(missing))


def read_combined(paths: list[Path]) -> str:
    text = ""
    for path in paths:
        if not path.is_file():
            die(f"config file not found: {path}")
        text += path.read_text(encoding="utf-8", errors="replace")
        if not text.endswith("\n"):
            text += "\n"
    return text


def defconfig_from_text(openwrt_root: Path, config_text: str, keep_config: bool) -> str:
    config_path = openwrt_root / ".config"
    old_config = config_path.read_bytes() if config_path.exists() else None
    wrote_config = False
    try:
        config_path.write_text(config_text if config_text.endswith("\n") else config_text + "\n", encoding="utf-8")
        wrote_config = True
        subprocess.run(["make", "defconfig"], cwd=openwrt_root, check=True)
        return config_path.read_text(encoding="utf-8", errors="replace")
    finally:
        if wrote_config and not keep_config:
            if old_config is None:
                config_path.unlink(missing_ok=True)
            else:
                config_path.write_bytes(old_config)


def resolve_indexes(args: argparse.Namespace, tmpdir: Path) -> list[Path]:
    paths = [Path(item) for item in os.environ.get("THIRD_PARTY_PACKAGE_INDEX_FILES", "").split()]
    paths.extend(Path(item) for item in args.third_party_index)
    if paths:
        for path in paths:
            if not path.is_file():
                die(f"third-party package index file not found: {path}")
        return paths
    urls = args.third_party_index_url or os.environ.get("THIRD_PARTY_PACKAGE_ADB_URLS", "").split() or DEFAULT_PACKAGE_ADB_URLS
    paths = []
    for index, url in enumerate(urls, 1):
        output = tmpdir / f"index-{index}.adb"
        print(f"fetch index: {url}", file=sys.stderr)
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            output.write_bytes(response.read())
        paths.append(output)
    return paths


def compute_missing(selected: dict[str, str], third_party: dict[str, PackageInfo]) -> list[str]:
    return [symbol for key, symbol in selected.items() if key not in third_party]


def config_paths(args: argparse.Namespace) -> list[Path]:
    if args.config:
        return [Path(path) for path in args.config]
    return [Path(path) for path in args.extra_config] + [Path(args.base_config)]


def excluded_packages_from_files(paths: list[str]) -> set[str]:
    excluded: set[str] = set()
    for item in paths:
        path = Path(item)
        if not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            package = raw_line.strip()
            if package and not package.startswith("#"):
                excluded.add(canon(package))
    return excluded


def run_generate(args: argparse.Namespace) -> None:
    openwrt_root = Path(args.openwrt_root) if args.openwrt_root else None
    if args.candidate_config:
        source_config = Path(args.candidate_config).read_text(encoding="utf-8", errors="replace")
        candidate_config = source_config
    else:
        if not openwrt_root:
            die("set --openwrt-root or --candidate-config")
        source_config = read_combined(config_paths(args))
        candidate_config = defconfig_from_text(openwrt_root, source_config, args.keep_openwrt_config)

    with tempfile.TemporaryDirectory(prefix="missing-packages.") as tmp:
        indexes = resolve_indexes(args, Path(tmp))
        third_party = merge_package_maps([parse_package_index(path) for path in indexes])
        if not third_party:
            die("no packages found in third-party indexes")
        selected = selected_packages_from_config(candidate_config)
        for key in disabled_packages_from_config(source_config) | excluded_packages_from_files(args.excluded_packages):
            selected.pop(key, None)
        missing = compute_missing(selected, third_party)

    missing_output_path = Path(args.missing_output)
    missing_output_path.parent.mkdir(parents=True, exist_ok=True)
    missing_output_path.write_text(render_missing_packages(missing), encoding="utf-8")
    print(f"selected packages: {len(selected)}")
    print(f"third-party index packages/provides: {len(third_party)}")
    print(f"missing packages: {len(missing)}")
    print(f"wrote missing package candidates: {missing_output_path}")


def assert_contains(path: Path, line: str) -> None:
    if line not in path.read_text(encoding="utf-8").splitlines():
        die(f"self-test expected line missing: {line}")


def assert_not_contains(path: Path, line: str) -> None:
    if line in path.read_text(encoding="utf-8").splitlines():
        die(f"self-test unexpected line present: {line}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="missing-packages-test.") as tmp:
        root = Path(tmp)
        candidate = root / ".config"
        index = root / "Packages"
        output = root / "missing-packages.txt"
        candidate.write_text(
            "\n".join(
                [
                    "CONFIG_PACKAGE_present=y",
                    "CONFIG_PACKAGE_provided-alias=m",
                    "CONFIG_PACKAGE_version-different=y",
                    "CONFIG_PACKAGE_kernel-bound=y",
                    "CONFIG_PACKAGE_missing-only=y",
                    "CONFIG_PACKAGE_disabled-only=y",
                    "# CONFIG_PACKAGE_disabled-only is not set",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        index.write_text(
            """
Package: present
Version: 1

Package: provider
Version: 1
Provides: provided-alias

Package: version-different
Version: 0

Package: kernel-bound
Version: 1
Depends: kernel (= 6.12.87~remote-r1)
""".lstrip(),
            encoding="utf-8",
        )
        run_generate(
            argparse.Namespace(
                base_config="",
                missing_output=str(output),
                openwrt_root=None,
                candidate_config=str(candidate),
                config=[],
                extra_config=[],
                excluded_packages=[],
                third_party_index=[str(index)],
                third_party_index_url=[],
                keep_openwrt_config=False,
            )
        )
        assert_contains(output, "missing-only")
        assert_not_contains(output, "present")
        assert_not_contains(output, "provided-alias")
        assert_not_contains(output, "version-different")
        assert_not_contains(output, "kernel-bound")
        assert_not_contains(output, "disabled-only")
    print("self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a local audit list of selected packages missing from third-party indexes.")
    parser.add_argument("--base-config", default="configs/JDCLoud.Taiyi.config")
    parser.add_argument("--config", action="append", default=[], help="config file to use instead of --extra-config plus --base-config")
    parser.add_argument("--missing-output", default="artifacts/JDCLoud.Taiyi.missing-packages.txt")
    parser.add_argument("--openwrt-root", default=os.environ.get("OPENWRT_PATH"))
    parser.add_argument("--extra-config", action="append", default=["configs/General.config"])
    parser.add_argument("--candidate-config")
    parser.add_argument("--excluded-packages", action="append", default=["configs/JDCLoud.Taiyi.excluded-packages"])
    parser.add_argument("--third-party-index", action="append", default=[])
    parser.add_argument("--third-party-index-url", action="append", default=[])
    parser.add_argument("--keep-openwrt-config", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        run_generate(args)


if __name__ == "__main__":
    main()

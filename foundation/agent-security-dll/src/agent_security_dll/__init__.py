"""Windows Guard artifacts built from the foundation sources."""

import hashlib
import json
import struct
from pathlib import Path

__version__ = "0.3.2"


def binary_directory() -> Path:
    """Root containing the per-architecture bundle directories."""
    package = Path(__file__).resolve().parent
    project = package.parents[1]
    if (project / "scripts" / "build-windows.ps1").is_file():
        return project / "build"
    return package / "bin"


def guard_library(architecture: str = "x64") -> Path:
    if architecture not in {"x64", "x86"}:
        raise ValueError(f"Unsupported Guard architecture: {architecture}")
    return binary_directory() / architecture / "agent_security_guard.dll"


PROTOCOL = 13
CAPABILITIES = {"file", "process", "network", "soft_delete", "operation_results"}
DETOURS_COMMIT = "e4bfd6b03e50de46b47abfbd1e46b384f0c5f833"


def _exports(data, architecture):
    def read(fmt, offset):
        return struct.unpack_from(fmt, data, offset)

    pe, = read("<I", 60)
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    machine, sections, _, _, _, optional_size, characteristics = read("<HHIIIHH", pe + 4)
    optional = pe + 24
    magic, = read("<H", optional)
    if (machine, magic) != {"x64": (0x8664, 0x20b), "x86": (0x14c, 0x10b)}[architecture]:
        raise ValueError("Invalid PE architecture")
    directory = 112 if architecture == "x64" else 96
    if not characteristics & 0x2000 or not 0 < sections <= 96 or optional_size < directory + 8:
        raise ValueError("Invalid DLL optional header")
    count, = read("<I", optional + directory - 4)
    if not count:
        raise ValueError("Missing PE data directories")
    export_rva, export_size = read("<II", optional + directory)
    header_size, = read("<I", optional + 60)
    table = optional + optional_size
    ranges = []
    for index in range(sections):
        virtual_size, address, raw_size, raw = read("<IIII", table + index * 40 + 8)
        if raw + raw_size > len(data):
            raise ValueError("Truncated DLL section")
        ranges.append((address, max(virtual_size, raw_size), raw, raw_size))

    def at(rva, size):
        if 0 <= rva and rva + size <= min(header_size, len(data)):
            return rva
        for address, length, raw, raw_size in ranges:
            if address <= rva and rva + size <= address + length and rva - address + size <= raw_size:
                return raw + rva - address
        raise ValueError("Invalid export RVA")

    if not export_rva or export_size < 40:
        raise ValueError("Missing DLL exports")
    entry = at(export_rva, 40)
    base, functions, names, function_rvas, name_rvas, ordinals = read("<IIIIII", entry + 16)
    if not 0 < names <= functions <= len(data) // 4:
        raise ValueError("Invalid export count")
    funcs, strings, orders = at(function_rvas, functions * 4), at(name_rvas, names * 4), at(ordinals, names * 2)
    exported = {}
    for index in range(names):
        pointer, = read("<I", strings + index * 4)
        position = at(pointer, 1)
        end = data.find(b"\0", position, min(position + 512, len(data)))
        if end < 0:
            raise ValueError("Invalid export name")
        ordinal, = read("<H", orders + index * 2)
        if ordinal >= functions:
            raise ValueError("Invalid export ordinal")
        target, = read("<I", funcs + ordinal * 4)
        if target and not export_rva <= target < export_rva + export_size:
            at(target, 1)
            exported[data[position:end].decode("ascii")] = base + ordinal
    return exported


def validate_library(path: Path, architecture: str, *, required_protocol: int = PROTOCOL,
                     standalone_recovery: bool = False) -> Path:
    if required_protocol != PROTOCOL:
        raise ValueError(f"Consumer requires Guard protocol {required_protocol}, loader supports {PROTOCOL}")
    try:
        manifest = json.loads(path.with_suffix(".manifest.json").read_text(encoding="utf-8-sig"))
        data = path.read_bytes()
        required = {"GuardMarker", "guard_open", "guard_close", "guard_prepare_session", "DetourFinishHelperProcess"}
        capabilities = CAPABILITIES | ({"standalone_recovery"} if architecture == "x64" else set())
        declared = set(manifest.get("capabilities", []))
        if standalone_recovery or "standalone_recovery" in declared:
            capabilities = capabilities | {"standalone_recovery"}
        if "standalone_recovery" in capabilities:
            required |= {"guard_prepare_process", "guard_recover_local"}
        targets = set(manifest.get("target_architectures", []))
        valid = (manifest.get("protocol") == PROTOCOL and manifest.get("architecture") == architecture
                 and manifest.get("platform") == "windows" and manifest.get("host_architecture") == "x64"
                 and manifest.get("hook_backend") == "detours" and manifest.get("detours_commit") == DETOURS_COMMIT
                 and architecture in targets and targets <= {"x64", "x86"}
                 and declared == capabilities
                 and manifest.get("sha256") == hashlib.sha256(data).hexdigest())
        exports = _exports(data, architecture)
        if not valid or not required <= exports.keys() or exports.get("DetourFinishHelperProcess") != 1:
            raise ValueError("Manifest, image or required exports mismatch")
    except (KeyError, TypeError, AttributeError, struct.error, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid Guard bundle: {path}") from exc
    return path


def validated_library(architecture: str = "x64", *, required_protocol: int = PROTOCOL,
                      standalone_recovery: bool = False) -> Path:
    return validate_library(guard_library(architecture), architecture, required_protocol=required_protocol,
                            standalone_recovery=standalone_recovery)

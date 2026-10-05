"""Inspect central-directory metadata without opening/decompressing members.

The raw-byte cap precedes ZipFile construction. Entry count is checked AFTER
stdlib has parsed all central-directory entries. Metadata completion is not
archive content validity, local-header consistency, or extraction safety.
"""

from io import BytesIO
import json
import re
import stat
import struct
import unicodedata
import zipfile

MAX_INPUT_BYTES = 65_536
MAX_ENTRIES = 16
MAX_OUTPUT_BYTES = 32_768
MAX_DECLARED_ENTRY = 262_144
MAX_DECLARED_TOTAL = 1_048_576
MAX_RATIO = 100
PREVIEW_CHARS = 128
RESERVED = re.compile(r"(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)", re.IGNORECASE)
NOT_VERIFIED = ["member_content", "crc", "local_header_agreement", "extraction_safety"]


def _report(status: str, reason: str, count: int | None = None, entries: list | None = None) -> dict:
    return {"status": status, "metadata_complete": status == "complete_metadata",
            "reason": reason, "entry_count": count, "entries": entries or [],
            "not_verified": list(NOT_VERIFIED)}


def _name_flags(name: str) -> set[str]:
    flags = set()
    if not name:
        flags.add("empty_name")
    if len(name) > 256:
        flags.add("long_name")
    if any(unicodedata.category(char) in ("Cc", "Cf", "Cs", "Zl", "Zp") for char in name):
        flags.add("control_or_format_character")
    if "\\" in name:
        flags.add("backslash_ambiguity")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        flags.add("absolute_or_unc_name")
    if re.match(r"^[a-zA-Z]:", normalized):
        flags.add("drive_name")
    parts = normalized.rstrip("/").split("/")
    for part in parts:
        if part in (".", ".."):
            flags.add("relative_path_component")
        if not part:
            flags.add("empty_path_component")
        if any(char in '<>:"|?*' for char in part):
            flags.add("windows_special_character")
        if part.endswith((" ", ".")):
            flags.add("trailing_dot_or_space")
        if RESERVED.match(part):
            flags.add("windows_reserved_name")
    if unicodedata.normalize("NFC", normalized) != normalized:
        flags.add("unicode_normalization")
    return flags


def _canonical(name: str) -> str:
    # Conservative comparison only: not a Windows/POSIX path resolver or a
    # guarantee that every possible filesystem alias has been modeled.
    components = name.replace("\\", "/").rstrip("/").split("/")
    return "/".join(unicodedata.normalize("NFC", part).casefold().rstrip(" .") for part in components)


def _extra_status(extra: bytes) -> str | None:
    """Validate TLV framing/scope only; stdlib decodes ZIP64, not this function."""
    offset = 0
    seen_zip64 = False
    unsupported = False
    while offset < len(extra):
        if len(extra) - offset < 4:
            return "malformed_extra"
        field, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if size > len(extra) - offset:
            return "malformed_extra"
        if field != 1:
            unsupported = True
        else:
            if seen_zip64:
                return "malformed_extra"
            seen_zip64 = True
            # Initial supported shape: one to three 64-bit fields. Disk-start
            # extensions/other shapes are not silently treated as supported.
            if size not in (8, 16, 24):
                unsupported = True
        offset += size
    return "unsupported_extra" if unsupported else None


def _preview(name: str) -> dict:
    return {"text": name[:PREVIEW_CHARS], "truncated": len(name) > PREVIEW_CHARS}


def analyze(raw: bytes) -> dict:
    """Return explicit bounded metadata outcomes for inert synthetic ZIP bytes.

    Input must be exact bytes, at most 64 KiB. Complete results may contain risk
    findings. Unsupported/malformed/over-limit results are incomplete. No report
    authorizes extraction. Original/effective names are decoded strings, not raw
    filename bytes; previews may be truncated while checks inspect full strings.
    """
    if type(raw) is not bytes:
        return _report("malformed", "invalid_input_type")
    if len(raw) > MAX_INPUT_BYTES:
        return _report("over_limit", "input_limit")
    try:
        with zipfile.ZipFile(BytesIO(raw), "r") as archive:
            infos = archive.infolist()
            count = len(infos)
            if count > MAX_ENTRIES:
                return _report("over_limit", "entry_count_limit", count)
            entries = []
            seen_names = {}
            unsupported = False
            malformed = False
            total = sum(info.file_size for info in infos)
            for index, info in enumerate(infos):
                flags = _name_flags(info.orig_filename) | _name_flags(info.filename)
                if info.orig_filename != info.filename:
                    flags.add("parser_changed_name")
                for name in (info.orig_filename, info.filename):
                    canonical = _canonical(name)
                    previous = seen_names.get(canonical)
                    if previous is not None and previous != index:
                        flags.add("name_collision")
                        entries[previous]["findings"] = sorted(set(entries[previous]["findings"]) | {"name_collision"})
                    seen_names[canonical] = index
                extra = _extra_status(info.extra)
                if extra:
                    flags.add(extra)
                    malformed |= extra == "malformed_extra"
                    unsupported |= extra == "unsupported_extra"
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    flags.add("unsupported_compression")
                    unsupported = True
                if info.flag_bits & ~((1 << 11) | (1 << 3)):
                    flags.add("unsupported_flags_or_encryption")
                    unsupported = True
                if info.volume != 0:
                    flags.add("unsupported_multidisk")
                    unsupported = True
                if stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                    flags.add("symlink_attribute")
                if info.file_size > MAX_DECLARED_ENTRY:
                    flags.add("declared_entry_size_limit")
                if total > MAX_DECLARED_TOTAL:
                    flags.add("declared_total_size_limit")
                if info.file_size > info.compress_size * MAX_RATIO:
                    flags.add("declared_ratio_limit")
                if info.compress_size > len(raw):
                    flags.add("declared_compressed_size_exceeds_input")
                if info.header_offset < 0 or info.header_offset >= len(raw):
                    flags.add("declared_header_offset_outside_input")
                entries.append({"index": index, "original_name": _preview(info.orig_filename),
                                "effective_name": _preview(info.filename),
                                "declared_size": info.file_size, "declared_compressed_size": info.compress_size,
                                "findings": sorted(flags)})
            if malformed:
                return _report("malformed", "malformed_extra", count, entries)
            if unsupported:
                return _report("unsupported", "unsupported_metadata", count, entries)
            return _report("complete_metadata", "metadata_only", count, entries)
    except NotImplementedError:
        return _report("unsupported", "unsupported_zip_version")
    except (zipfile.BadZipFile, UnicodeError, ValueError, OverflowError, struct.error, EOFError):
        return _report("malformed", "invalid_zip_metadata")


def serialize_report(report: dict) -> bytes:
    """Serialize one analyzer report, including newline, within the output cap.

    Oversized output becomes an explicit incomplete outcome, not a silently
    truncated complete report. Only use with reports from this bounded analyzer.
    """
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        return serialize_report(_report("over_limit", "output_limit"))
    return encoded

"""Small inert ZIP fixtures, generated in memory; never extracted or executed.

Central-record mutations deliberately need not match local headers/payloads.
These helpers are fixture construction, not a replacement ZIP name parser.
"""

from binascii import crc32
from io import BytesIO
import stat
import struct
import zipfile


def make_zip(names: tuple[str, ...] = ("notes.txt",), extra: bytes = b"", symlink: bool = False) -> bytes:
    """Construct trusted synthetic fixtures with a fixed tiny text payload."""
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.extra = extra
            if symlink:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"inert")
    return buffer.getvalue()


def patch_central(raw: bytes, *, name: bytes | None = None, flags: int | None = None,
                  size: int | None = None, compressed: int | None = None,
                  method: int | None = None, volume: int | None = None) -> bytes:
    """Mutate the first canonical fixture's central record, not member data.

    Offsets follow the ZIP central-directory structure. Only trusted lab
    fixtures use this writer; it is not called by the analyzer on input data.
    """
    output = bytearray(raw)
    offset = raw.index(b"PK\x01\x02")
    if name is not None:
        length, = struct.unpack_from("<H", output, offset + 28)
        if len(name) != length:
            raise ValueError("fixture replacement name must preserve length")
        output[offset + 46:offset + 46 + length] = name
    for value, displacement, format_code in ((flags, 8, "H"), (method, 10, "H"),
                                              (compressed, 20, "I"), (size, 24, "I"), (volume, 34, "H")):
        if value is not None:
            struct.pack_into("<" + format_code, output, offset + displacement, value)
    return bytes(output)


def unicode_override() -> bytes:
    """Unicode Path extra alters effective name in the inspected CPython 3.13."""
    alternate = b"../outside.txt"
    data = struct.pack("<BI", 1, crc32(b"base.txt")) + alternate
    return make_zip(("base.txt",), struct.pack("<HH", 0x7075, len(data)) + data)


def demo_cases() -> list[tuple[str, bytes, str]]:
    """Return fixed metadata scenarios and structural outcome expectations."""
    return [
        ("Ordinary synthetic ZIP", make_zip(), "complete_metadata"),
        ("Traversal name", make_zip(("../outside.txt",)), "complete_metadata"),
        ("Case-normalized collision", make_zip(("Notes.txt", "notes.txt")), "complete_metadata"),
        ("NUL in original name", patch_central(make_zip(("base.txt",)), name=b"ba\x00e.txt"), "complete_metadata"),
        ("Symlink attribute", make_zip(symlink=True), "complete_metadata"),
        ("Unicode Path extra", unicode_override(), "unsupported"),
        ("Seventeen entries", make_zip(tuple(f"n{i}.txt" for i in range(17))), "over_limit"),
        ("Malformed bytes", b"inert non-ZIP bytes", "malformed"),
    ]

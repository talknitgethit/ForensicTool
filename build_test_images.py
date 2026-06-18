"""Build synthetic MBR and GPT disk images for testing partition parsing."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

SECTOR = 512


def build_mbr(path: Path, total_sectors: int = 2048) -> None:
    disk = bytearray(total_sectors * SECTOR)
    mbr = bytearray(SECTOR)

    def entry(boot: int, ptype: int, start_lba: int, count: int) -> bytes:
        return struct.pack(
            "<B3sB3sII", boot, b"\x00\x00\x00", ptype, b"\x00\x00\x00", start_lba, count
        )

    mbr[446:462] = entry(0x80, 0x0C, 2048 // 1, 512)  # FAT32 (LBA), bootable
    mbr[462:478] = entry(0x00, 0x83, 1024, 512)  # Linux
    mbr[510:512] = struct.pack("<H", 0xAA55)
    disk[0:SECTOR] = mbr
    path.write_bytes(disk)


def build_gpt(path: Path, total_sectors: int = 4096) -> None:
    disk = bytearray(total_sectors * SECTOR)

    # Protective MBR.
    pmbr = bytearray(SECTOR)
    pmbr[446:462] = struct.pack(
        "<B3sB3sII", 0x00, b"\x00\x00\x00", 0xEE, b"\x00\x00\x00", 1, total_sectors - 1
    )
    pmbr[510:512] = struct.pack("<H", 0xAA55)
    disk[0:SECTOR] = pmbr

    entry_size = 128
    entry_count = 128
    entries_lba = 2
    array = bytearray(entry_size * entry_count)

    def guid(s: str) -> bytes:
        s = s.replace("-", "")
        d1 = struct.pack("<I", int(s[0:8], 16))
        d2 = struct.pack("<H", int(s[8:12], 16))
        d3 = struct.pack("<H", int(s[12:16], 16))
        d4 = bytes.fromhex(s[16:20])
        d5 = bytes.fromhex(s[20:32])
        return d1 + d2 + d3 + d4 + d5

    esp = guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
    linux = guid("0FC63DAF-8483-4772-8E79-3D69D8477DE4")
    unique = guid("12345678-1234-1234-1234-1234567890AB")

    def part(type_guid: bytes, first: int, last: int, name: str) -> bytes:
        name_bytes = name.encode("utf-16-le").ljust(72, b"\x00")[:72]
        return type_guid + unique + struct.pack("<QQQ", first, last, 0) + name_bytes

    array[0:128] = part(esp, 34, 100, "EFI System")
    array[128:256] = part(linux, 101, 2000, "Linux root")

    array_crc = zlib.crc32(array) & 0xFFFFFFFF

    header = bytearray(92)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)  # revision 1.0
    struct.pack_into("<I", header, 12, 92)  # header size
    struct.pack_into("<I", header, 20, 0)  # reserved
    struct.pack_into("<Q", header, 24, 1)  # current LBA
    struct.pack_into("<Q", header, 32, total_sectors - 1)  # backup LBA
    struct.pack_into("<Q", header, 40, 34)  # first usable
    struct.pack_into("<Q", header, 48, total_sectors - 34)  # last usable
    header[56:72] = guid("AABBCCDD-EEFF-0011-2233-445566778899")  # disk GUID
    struct.pack_into("<Q", header, 72, entries_lba)
    struct.pack_into("<I", header, 80, entry_count)
    struct.pack_into("<I", header, 84, entry_size)
    struct.pack_into("<I", header, 88, array_crc)
    header_crc = zlib.crc32(header) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, header_crc)

    disk[SECTOR : SECTOR + len(header)] = header
    disk[entries_lba * SECTOR : entries_lba * SECTOR + len(array)] = array
    path.write_bytes(disk)


if __name__ == "__main__":
    build_mbr(Path("mbr_test.img"))
    build_gpt(Path("gpt_test.img"))
    print("Wrote mbr_test.img and gpt_test.img")

"""MBR and GPT partition table parsing (read-only)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forensic_tool.image import DiskImage


MBR_SIGNATURE = 0xAA55
MBR_PARTITION_TABLE_OFFSET = 446
MBR_PARTITION_ENTRY_SIZE = 16
MBR_PARTITION_COUNT = 4
MBR_PROTECTIVE_TYPE = 0xEE
MBR_EXTENDED_TYPES = frozenset({0x05, 0x0F, 0x85})

GPT_SIGNATURE = b"EFI PART"

# Common MBR partition type codes -> human readable description.
MBR_TYPE_NAMES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 (<32 MB)",
    0x05: "Extended (CHS)",
    0x06: "FAT16B",
    0x07: "NTFS / exFAT / HPFS",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x82: "Linux swap",
    0x83: "Linux",
    0x85: "Linux extended",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA8: "Apple UFS",
    0xAB: "Apple Boot",
    0xAF: "Apple HFS / HFS+",
    0xEE: "GPT protective",
    0xEF: "EFI System (ESP)",
    0xFD: "Linux RAID",
}

# Common GPT partition type GUIDs -> human readable description.
GPT_TYPE_NAMES = {
    "00000000-0000-0000-0000-000000000000": "Unused entry",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System (ESP)",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR partition scheme",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved (MSR)",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "44479540-F297-41B2-9AF7-D131D5F0458A": "Linux root (x86)",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
    "55465300-0000-11AA-AA11-00306543ECAC": "Apple UFS",
    "426F6F74-0000-11AA-AA11-00306543ECAC": "Apple Boot (Recovery)",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD data",
}


@dataclass
class Partition:
    scheme: str
    index: int
    type_id: str
    type_name: str
    start_lba: int
    sector_count: int
    start_offset: int
    size_bytes: int
    bootable: bool = False
    name: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "scheme": self.scheme,
            "index": self.index,
            "type_id": self.type_id,
            "type_name": self.type_name,
            "start_lba": self.start_lba,
            "sector_count": self.sector_count,
            "start_offset": self.start_offset,
            "size_bytes": self.size_bytes,
            "bootable": self.bootable,
            "name": self.name,
        }


@dataclass
class PartitionTable:
    scheme: str
    partitions: list[Partition]
    disk_guid: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "scheme": self.scheme,
            "disk_guid": self.disk_guid,
            "partition_count": len(self.partitions),
            "partitions": [partition.to_dict() for partition in self.partitions],
        }


def _format_guid(raw: bytes) -> str:
    """Format a 16-byte mixed-endian GUID as an upper-case string."""
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10]
    d5 = raw[10:16]
    return (
        f"{d1:08X}-{d2:04X}-{d3:04X}-"
        f"{d4.hex().upper()}-{d5.hex().upper()}"
    )


def _parse_mbr(image: DiskImage, sector0: bytes) -> PartitionTable:
    partitions: list[Partition] = []
    for index in range(MBR_PARTITION_COUNT):
        entry_offset = MBR_PARTITION_TABLE_OFFSET + index * MBR_PARTITION_ENTRY_SIZE
        entry = sector0[entry_offset : entry_offset + MBR_PARTITION_ENTRY_SIZE]
        boot_flag, part_type = entry[0], entry[4]
        start_lba, sector_count = struct.unpack_from("<II", entry, 8)

        if part_type == 0x00 and start_lba == 0 and sector_count == 0:
            continue

        partitions.append(
            Partition(
                scheme="MBR",
                index=index + 1,
                type_id=f"0x{part_type:02X}",
                type_name=MBR_TYPE_NAMES.get(part_type, "Unknown"),
                start_lba=start_lba,
                sector_count=sector_count,
                start_offset=start_lba * image.sector_size,
                size_bytes=sector_count * image.sector_size,
                bootable=boot_flag == 0x80,
            )
        )

    image.audit.record(
        "parse_partition_table",
        scheme="MBR",
        partition_count=len(partitions),
    )
    return PartitionTable(scheme="MBR", partitions=partitions)


def _parse_gpt(image: DiskImage) -> PartitionTable:
    sector_size = image.sector_size
    header = image.read_bytes(sector_size, sector_size)
    if header[:8] != GPT_SIGNATURE:
        raise ValueError("GPT header signature not found at LBA 1")

    disk_guid = _format_guid(header[56:72])
    entries_lba, entry_count, entry_size = struct.unpack_from("<QII", header, 72)

    array_offset = entries_lba * sector_size
    array_bytes = image.read_bytes(array_offset, entry_count * entry_size)

    partitions: list[Partition] = []
    for index in range(entry_count):
        base = index * entry_size
        entry = array_bytes[base : base + entry_size]
        if len(entry) < 56:
            break

        type_guid_raw = entry[0:16]
        if type_guid_raw == b"\x00" * 16:
            continue

        type_guid = _format_guid(type_guid_raw)
        first_lba, last_lba, attributes = struct.unpack_from("<QQQ", entry, 32)
        name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        sector_count = last_lba - first_lba + 1 if last_lba >= first_lba else 0

        partitions.append(
            Partition(
                scheme="GPT",
                index=index + 1,
                type_id=type_guid,
                type_name=GPT_TYPE_NAMES.get(type_guid, "Unknown"),
                start_lba=first_lba,
                sector_count=sector_count,
                start_offset=first_lba * sector_size,
                size_bytes=sector_count * sector_size,
                bootable=bool(attributes & (1 << 2)),
                name=name,
            )
        )

    image.audit.record(
        "parse_partition_table",
        scheme="GPT",
        disk_guid=disk_guid,
        partition_count=len(partitions),
    )
    return PartitionTable(scheme="GPT", partitions=partitions, disk_guid=disk_guid)


def detect_partition_table(image: DiskImage) -> PartitionTable | None:
    """Detect and parse the partition table, returning None if none is found."""
    if image.size < image.sector_size:
        image.audit.record("detect_partition_table", result="image_too_small")
        return None

    sector0 = image.read_bytes(0, image.sector_size)
    if len(sector0) < MBR_PARTITION_TABLE_OFFSET + 2:
        image.audit.record("detect_partition_table", result="image_too_small")
        return None

    signature = struct.unpack_from("<H", sector0, 510)[0]
    if signature != MBR_SIGNATURE:
        image.audit.record("detect_partition_table", result="no_signature")
        return None

    # A protective MBR (type 0xEE) indicates a GPT disk.
    first_type = sector0[MBR_PARTITION_TABLE_OFFSET + 4]
    if first_type == MBR_PROTECTIVE_TYPE:
        try:
            return _parse_gpt(image)
        except ValueError:
            # Fall back to treating it as a plain MBR if GPT parsing fails.
            return _parse_mbr(image, sector0)

    return _parse_mbr(image, sector0)

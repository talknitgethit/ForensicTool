"""Export forensic findings to JSON or plain text."""

from __future__ import annotations

import json
from pathlib import Path

from forensic_tool.audit import AuditLog
from forensic_tool.hexdump import format_hex_dump
from forensic_tool.image import DiskImage
from forensic_tool.partition import PartitionTable


def export_json(
    image: DiskImage,
    audit: AuditLog,
    path: Path,
    *,
    partition_table: PartitionTable | None = None,
) -> None:
    payload = {
        "tool": "forensic-tool",
        "version": "0.1.0",
        "image": image.summary(),
        "partitions": None if partition_table is None else partition_table.to_dict(),
        "audit_log": audit.to_dict(),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    audit.record("export_report", format="json", path=str(path.resolve()))


def export_text(
    image: DiskImage,
    audit: AuditLog,
    path: Path,
    *,
    partition_table: PartitionTable | None = None,
) -> None:
    lines: list[str] = [
        "FORENSIC TOOL REPORT",
        "====================",
        "",
        f"Image path:    {image.path}",
        f"File size:     {image.size:,} bytes",
        f"Sector size:   {image.sector_size} bytes",
        f"Sector count:  {image.sector_count:,}",
        "",
    ]

    if image.hashes:
        lines.extend(
            [
                "Hashes",
                "------",
                f"MD5:    {image.hashes.md5}",
                f"SHA1:   {image.hashes.sha1}",
                f"SHA256: {image.hashes.sha256}",
                "",
            ]
        )
    else:
        lines.extend(["Hashes", "------", "(not calculated)", ""])

    if partition_table is not None:
        lines.append("Partitions")
        lines.append("----------")
        lines.append(f"Scheme: {partition_table.scheme}")
        if partition_table.disk_guid:
            lines.append(f"Disk GUID: {partition_table.disk_guid}")
        if partition_table.partitions:
            for part in partition_table.partitions:
                boot = " [bootable]" if part.bootable else ""
                name = f' "{part.name}"' if part.name else ""
                lines.append(
                    f"  #{part.index} {part.type_name} ({part.type_id}){boot}{name}"
                )
                lines.append(
                    f"      start LBA {part.start_lba:,}, "
                    f"{part.sector_count:,} sectors, "
                    f"offset {part.start_offset:,}, "
                    f"{part.size_bytes:,} bytes"
                )
        else:
            lines.append("  (table present but empty)")
        lines.append("")

    if image._sector_reads:
        lines.append("Sector Reads")
        lines.append("------------")
        for sector in image._sector_reads:
            lines.extend(
                [
                    "",
                    f"Sector {sector.sector_number} @ offset {sector.offset} "
                    f"({sector.length} bytes"
                    f"{', truncated' if sector.truncated else ''})",
                    format_hex_dump(sector.data, offset=sector.offset),
                ]
            )
        lines.append("")

    lines.extend(["Audit Log", "---------"])
    for entry in audit.entries:
        details = ", ".join(f"{key}={value}" for key, value in entry.details.items())
        lines.append(f"[{entry.timestamp}] {entry.action}: {details}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit.record("export_report", format="text", path=str(path.resolve()))

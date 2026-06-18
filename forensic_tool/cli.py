"""Command-line interface for the forensic disk image tool."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from forensic_tool.audit import AuditLog
from forensic_tool.hexdump import format_hex_dump
from forensic_tool.image import DiskImage
from forensic_tool.partition import PartitionTable, detect_partition_table
from forensic_tool.report import export_json, export_text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic",
        description="Read-only forensic disk image analyzer (image files only).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    open_parser = subparsers.add_parser("open", help="Open a disk image and show metadata")
    open_parser.add_argument("image", type=Path, help="Path to disk image file")
    open_parser.add_argument(
        "--hash",
        action="store_true",
        help="Calculate MD5, SHA1, and SHA256 hashes",
    )

    sector_parser = subparsers.add_parser("sector", help="Read and display a sector in hex")
    sector_parser.add_argument("image", type=Path, help="Path to disk image file")
    sector_parser.add_argument("number", type=int, help="Sector number (0-based)")
    sector_parser.add_argument(
        "--sector-size",
        type=int,
        default=512,
        help="Bytes per sector (default: 512)",
    )

    partitions_parser = subparsers.add_parser(
        "partitions", help="Detect and list MBR/GPT partitions"
    )
    partitions_parser.add_argument("image", type=Path, help="Path to disk image file")

    report_parser = subparsers.add_parser("report", help="Generate a forensic report")
    report_parser.add_argument("image", type=Path, help="Path to disk image file")
    report_parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Report format (default: json)",
    )
    report_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output file path",
    )
    report_parser.add_argument(
        "--sector",
        type=int,
        action="append",
        default=[],
        metavar="N",
        help="Include sector N in the report (repeatable)",
    )
    report_parser.add_argument(
        "--partitions",
        action="store_true",
        help="Detect and include the partition table in the report",
    )

    return parser


def _print_partition_table(table: PartitionTable | None) -> None:
    if table is None:
        print("Partitions:    none detected (no MBR/GPT signature)")
        return

    print(f"Partition map: {table.scheme}")
    if table.disk_guid:
        print(f"Disk GUID:     {table.disk_guid}")
    if not table.partitions:
        print("               (table present but empty)")
        return

    print()
    header = (
        f"{'#':>2}  {'Type':<24} {'Type ID':<14} "
        f"{'Start LBA':>12} {'Sectors':>12} {'Size':>12}  Name"
    )
    print(header)
    print("-" * len(header))
    for part in table.partitions:
        boot = "*" if part.bootable else " "
        size_mb = part.size_bytes / (1024 * 1024)
        size = f"{size_mb:,.1f} MB" if part.size_bytes else "0"
        type_id = part.type_id if len(part.type_id) <= 14 else part.type_id[:11] + "..."
        print(
            f"{part.index:>2}{boot} {part.type_name:<24.24} {type_id:<14} "
            f"{part.start_lba:>12,} {part.sector_count:>12,} {size:>12}  {part.name}"
        )


def _cmd_open(args: argparse.Namespace) -> int:
    audit = AuditLog()
    with DiskImage(args.image, audit=audit) as image:
        print(f"Image:         {image.path}")
        print(f"File size:     {image.size:,} bytes")
        print(f"Sector size:   {image.sector_size} bytes")
        print(f"Sector count:  {image.sector_count:,}")

        print()
        _print_partition_table(detect_partition_table(image))

        if args.hash:
            print("\nCalculating hashes...")
            hashes = image.calculate_hashes()
            print(f"MD5:           {hashes.md5}")
            print(f"SHA1:          {hashes.sha1}")
            print(f"SHA256:        {hashes.sha256}")
    return 0


def _cmd_partitions(args: argparse.Namespace) -> int:
    audit = AuditLog()
    with DiskImage(args.image, audit=audit) as image:
        print(f"Image:         {image.path}")
        print(f"Sector size:   {image.sector_size} bytes")
        print()
        _print_partition_table(detect_partition_table(image))
    return 0


def _cmd_sector(args: argparse.Namespace) -> int:
    audit = AuditLog()
    with DiskImage(args.image, audit=audit) as image:
        image.sector_size = args.sector_size
        image.sector_count = (image.size + image.sector_size - 1) // image.sector_size
        sector = image.read_sector(args.number, sector_size=args.sector_size)

        print(f"Image:         {image.path}")
        print(f"Sector:        {sector.sector_number}")
        print(f"Offset:        {sector.offset}")
        print(f"Length:        {sector.length} bytes")
        if sector.truncated:
            print("Note:          Partial sector (image ends before full sector boundary)")
        print()
        print(format_hex_dump(sector.data, offset=sector.offset))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    audit = AuditLog()
    with DiskImage(args.image, audit=audit) as image:
        image.calculate_hashes()
        for sector_number in args.sector:
            image.read_sector(sector_number)

        table = detect_partition_table(image) if args.partitions else None

        if args.format == "json":
            export_json(image, audit, args.output, partition_table=table)
        else:
            export_text(image, audit, args.output, partition_table=table)

        print(f"Report saved:  {args.output.resolve()}")
        print(f"Format:        {args.format}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "open":
            return _cmd_open(args)
        if args.command == "sector":
            return _cmd_sector(args)
        if args.command == "partitions":
            return _cmd_partitions(args)
        if args.command == "report":
            return _cmd_report(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

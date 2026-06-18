# Forensic Tool v1

Read-only forensic analyzer for **disk image files only** — no raw drive access.

## Features

- Open a disk image and show file size / sector layout
- Detect and parse **MBR** and **GPT** partition tables
- Calculate MD5, SHA1, and SHA256 hashes
- Read a sector by number (with a configurable sector size) and display hex dumps
- Handle partial/truncated trailing sectors gracefully
- Audit log of all operations (timestamped, UTC)
- Export findings to JSON or plain text, optionally embedding multiple sector
  dumps and the partition table

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Create a small test image
python3 -c "open('test.img','wb').write(b'FORENSIC' + b'\\x00'*504)"

# 1. Open image
forensic open test.img --hash

# 2. Read sector 0 (use --sector-size for non-512-byte sectors)
forensic sector test.img 0
forensic sector disk.img 2048 --sector-size 4096

# 3. List partitions (MBR or GPT)
forensic partitions disk.img

# 4. Save report (multiple --sector flags and/or the partition table)
forensic report test.img --sector 0 -o report.json
forensic report disk.img --sector 0 --sector 2048 --partitions -o report.json
forensic report test.img --sector 0 --format text -o report.txt
```

## Partition support

`forensic partitions <image>` (and `forensic open <image>`) automatically
detect the partition scheme:

- **MBR** — parses the 4 primary entries at offset 446, reporting the partition
  type code, bootable flag, start LBA, and size.
- **GPT** — detected via the protective MBR (type `0xEE`), then parses the GPT
  header at LBA 1 and the partition entry array, reporting the disk GUID,
  partition type GUID, name, start LBA, and size.

Common MBR type codes and GPT type GUIDs are mapped to human-readable names.
Pass `--partitions` to `forensic report` to embed the full partition table in
the JSON/text output. You can generate sample MBR and GPT images for testing
with `python3 build_test_images.py`, which writes `mbr_test.img` and
`gpt_test.img` into the current directory.

## Commands

| Command | Description |
|---------|-------------|
| `forensic open <image> [--hash]` | Show image metadata + partition table; optionally hash |
| `forensic sector <image> <n> [--sector-size N]` | Read sector `n` and print hex dump (default sector size 512) |
| `forensic partitions <image>` | Detect and list MBR/GPT partitions |
| `forensic report <image> -o <file> [--sector N ...] [--partitions] [--format json\|text]` | Export report (JSON by default) with hashes, sector dumps, partition table, and audit log |

## Safety

This tool only opens regular files (`.img`, `.dd`, `.raw`, etc.). It never enumerates or reads attached physical drives.

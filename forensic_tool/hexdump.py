"""Hex dump formatting for sector data."""

from __future__ import annotations


def format_hex_dump(
    data: bytes,
    *,
    offset: int = 0,
    bytes_per_line: int = 16,
) -> str:
    lines: list[str] = []
    for line_start in range(0, len(data), bytes_per_line):
        chunk = data[line_start : line_start + bytes_per_line]
        address = f"{offset + line_start:08x}"
        hex_parts = [f"{byte:02x}" for byte in chunk]
        hex_left = " ".join(hex_parts[:8]).ljust(23)
        hex_right = " ".join(hex_parts[8:]).ljust(23)
        ascii_repr = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{address}  {hex_left} {hex_right}  |{ascii_repr}|")
    return "\n".join(lines)

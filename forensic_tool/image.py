"""Read-only disk image access."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from forensic_tool.audit import AuditLog


DEFAULT_SECTOR_SIZE = 512


@dataclass(frozen=True)
class ImageHashes:
    md5: str
    sha1: str
    sha256: str


@dataclass
class SectorRead:
    sector_number: int
    sector_size: int
    offset: int
    length: int
    data: bytes
    truncated: bool


class DiskImage:
    def __init__(self, path: Path, *, audit: AuditLog | None = None) -> None:
        self.path = path.resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"Image file not found: {self.path}")
        self.audit = audit or AuditLog()
        self._file = self.path.open("rb")
        self.size = self.path.stat().st_size
        self.sector_size = DEFAULT_SECTOR_SIZE
        self.sector_count = (self.size + self.sector_size - 1) // self.sector_size
        self.hashes: ImageHashes | None = None
        self._sector_reads: list[SectorRead] = []

        self.audit.record(
            "open_image",
            path=str(self.path),
            size_bytes=self.size,
            sector_size=self.sector_size,
            sector_count=self.sector_count,
        )

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> DiskImage:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def calculate_hashes(self, *, chunk_size: int = 1024 * 1024) -> ImageHashes:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        self._file.seek(0)
        while True:
            chunk = self._file.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

        self._file.seek(0)
        self.hashes = ImageHashes(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
        )
        self.audit.record(
            "calculate_hashes",
            path=str(self.path),
            md5=self.hashes.md5,
            sha1=self.hashes.sha1,
            sha256=self.hashes.sha256,
        )
        return self.hashes

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ValueError("Offset must be >= 0")
        if length < 0:
            raise ValueError("Length must be >= 0")
        if offset > self.size:
            raise ValueError(
                f"Offset {offset} is out of range (image is {self.size} bytes)"
            )

        self._file.seek(offset)
        data = self._file.read(length)
        self.audit.record(
            "read_bytes",
            offset=offset,
            requested=length,
            bytes_read=len(data),
        )
        return data

    def read_sector(self, sector_number: int, *, sector_size: int | None = None) -> SectorRead:
        size = sector_size or self.sector_size
        if sector_number < 0:
            raise ValueError("Sector number must be >= 0")

        offset = sector_number * size
        if offset >= self.size and self.size > 0:
            raise ValueError(
                f"Sector {sector_number} is out of range "
                f"(image has {self.sector_count} sectors of {size} bytes)"
            )

        self._file.seek(offset)
        data = self._file.read(size)
        truncated = len(data) < size and offset + len(data) == self.size

        result = SectorRead(
            sector_number=sector_number,
            sector_size=size,
            offset=offset,
            length=len(data),
            data=data,
            truncated=truncated,
        )
        self._sector_reads.append(result)
        self.audit.record(
            "read_sector",
            sector_number=sector_number,
            sector_size=size,
            offset=offset,
            bytes_read=len(data),
            truncated=truncated,
        )
        return result

    def summary(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "size_bytes": self.size,
            "sector_size": self.sector_size,
            "sector_count": self.sector_count,
            "hashes": None
            if self.hashes is None
            else {
                "md5": self.hashes.md5,
                "sha1": self.hashes.sha1,
                "sha256": self.hashes.sha256,
            },
            "sectors_read": [
                {
                    "sector_number": sector.sector_number,
                    "offset": sector.offset,
                    "length": sector.length,
                    "truncated": sector.truncated,
                }
                for sector in self._sector_reads
            ],
        }

"""Audit log for forensic operations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEntry:
    timestamp: str
    action: str
    details: dict[str, Any]


@dataclass
class AuditLog:
    entries: list[AuditEntry] = field(default_factory=list)

    def record(self, action: str, **details: Any) -> None:
        self.entries.append(
            AuditEntry(timestamp=_utc_now(), action=action, details=details)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": _utc_now(),
            "entry_count": len(self.entries),
            "entries": [asdict(entry) for entry in self.entries],
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

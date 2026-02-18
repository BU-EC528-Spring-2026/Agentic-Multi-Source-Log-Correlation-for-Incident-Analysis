from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional

@dataclass(frozen=True)
class Event:
    """Unified event model across sources."""
    ts: float                 # epoch seconds (UTC)
    source: str               # e.g., host, auth, network, metrics
    message: str              # human-readable message
    level: Optional[str] = None
    fields: Dict[str, Any] = None

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "source": self.source,
            "level": self.level,
            "message": self.message,
            "fields": self.fields or {},
        }

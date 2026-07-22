from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


class ProgressWriter:
    """Append progress events as UTF-8 JSON Lines."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def emit(self, stage: str, current: int, total: int, message: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "stage": stage,
            "current": current,
            "total": total,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        with self.path.open("a", encoding="utf-8") as progress_file:
            progress_file.write(json.dumps(event, ensure_ascii=False) + "\n")

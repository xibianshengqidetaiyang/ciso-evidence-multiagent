from __future__ import annotations
from pathlib import Path
import json
from datetime import datetime, timezone

from app.config import STORAGE_DIR

LOG_FILE = STORAGE_DIR / "pipeline_logs.jsonl"
REVIEW_QUEUE = STORAGE_DIR / "manual_review_queue.jsonl"

STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def _write_line(path: Path, payload: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def log_event(event_type: str, payload: dict) -> None:
    _write_line(
        LOG_FILE,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
        },
    )


def enqueue_manual_review(payload: dict) -> None:
    _write_line(
        REVIEW_QUEUE,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        },
    )

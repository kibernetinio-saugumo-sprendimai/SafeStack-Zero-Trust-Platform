"""Deterministic SOC event collector and security rule detector."""
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Union
from .common import read_regular, resolve_parent

REQUIRED_EVENT_FIELDS = {"timestamp", "kind", "source", "subject", "success"}


def validate_event(event: Any) -> List[str]:
    """Validate that an event structure adheres to the SOC event format."""
    if not isinstance(event, dict):
        return ["event must be an object"]

    errors = ["missing: " + k for k in sorted(REQUIRED_EVENT_FIELDS - set(event.keys()))]
    if "success" in event and not isinstance(event["success"], bool):
        errors.append("success must be boolean")
    return errors


def append_event(path: Union[str, Path], event: Dict[str, Any]) -> None:
    """Validate and securely append a JSON SOC event with fsync and 0600 mode."""
    errors = validate_event(event)
    if errors:
        raise ValueError("; ".join(errors))

    target = Path(path).expanduser()
    if target.is_symlink():
        raise ValueError(f"Event target cannot be a symlink: {target}")

    resolve_parent(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        raise


def read_events(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Read SOC events line-by-line from a regular file, rejecting symlinks."""
    content = read_regular(path).decode("utf-8")
    rows = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                rows.append(parsed)
        except json.JSONDecodeError:
            continue
    return rows


def detect(events: List[Dict[str, Any]], failed_threshold: int = 5) -> List[Dict[str, Any]]:
    """Analyze events and generate actionable alerts for security anomalies."""
    if not isinstance(events, list):
        return []

    failures = Counter(
        e.get("subject", "unknown")
        for e in events
        if isinstance(e, dict) and e.get("kind") == "authentication" and e.get("success") is False
    )

    alerts = []
    for subject, count in failures.items():
        if count >= failed_threshold:
            alerts.append({
                "type": "brute_force_suspected",
                "subject": subject,
                "count": count,
                "severity": "high",
            })

    for e in events:
        if not isinstance(e, dict):
            continue
        if e.get("kind") == "authorization":
            reason = e.get("reason")
            if reason in ("device_not_registered", "no_matching_policy"):
                alerts.append({
                    "type": "unauthorized_access_attempt",
                    "subject": e.get("subject"),
                    "source": e.get("source"),
                    "severity": "medium",
                })
            elif reason == "device_posture_below_policy":
                alerts.append({
                    "type": "posture_violation",
                    "subject": e.get("subject"),
                    "source": e.get("source"),
                    "severity": "high",
                })
    return alerts

# SPDX-License-Identifier: AGPL-3.0-only
"""The live switch is two separate records. Either one alone stays off.

worker.json ``enabled`` is the install flag. ``activation-rollback.json`` is
the approval record. Activate writes who approved it and when. Deactivate
flips that record off. The packaged template stays unexecuted.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.private_io import atomic_write_private, ensure_private_dir

RECORD_NAME = "activation-rollback.json"


def record_path(root: Path) -> Path:
    return root / RECORD_NAME


def is_activated(root: Path) -> bool:
    path = record_path(root)
    if not path.is_file() or path.is_symlink():
        return False
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError):
        return False
    if not isinstance(raw, dict):
        return False
    return (
        raw.get("executed") is True
        and raw.get("activation_enabled") is True
        and bool(str(raw.get("approved_by", "")).strip())
        and bool(str(raw.get("approved_at", "")).strip())
        and bool(str(raw.get("approval_reference", "")).strip())
    )


def activate(root: Path, approved_by: str, reference: str, *, now: datetime | None = None) -> None:
    approver = _name(approved_by, "approved-by")
    ticket = _name(reference, "approval-reference")
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = _load(root)
    record["executed"] = True
    record["activation_enabled"] = True
    record["approved_by"] = approver
    record["approved_at"] = stamp
    record["approval_reference"] = ticket
    _write(root, record)


def deactivate(root: Path, approved_by: str, *, now: datetime | None = None) -> None:
    approver = _name(approved_by, "approved-by")
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = _load(root)
    record["executed"] = False
    record["activation_enabled"] = False
    record["deactivated_by"] = approver
    record["deactivated_at"] = stamp
    _write(root, record)


def _load(root: Path) -> dict[str, object]:
    path = record_path(root)
    if not path.is_file() or path.is_symlink():
        return {"executed": False, "activation_enabled": False}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError) as exc:
        raise Forbidden("activation record is unreadable or malformed") from exc
    if not isinstance(raw, dict):
        raise Forbidden("activation record is not an object")
    return raw


def _write(root: Path, record: dict[str, object]) -> None:
    ensure_private_dir(root)
    atomic_write_private(record_path(root), (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def _name(value: str, label: str) -> str:
    text = value.strip()
    if not text or any(char in text for char in "\r\n"):
        raise Forbidden(f"activation requires {label}")
    return text

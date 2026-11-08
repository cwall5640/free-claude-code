# SPDX-License-Identifier: AGPL-3.0-only
"""Durable assignment status. Locking is local and does not call GitHub."""

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from free_claude_code.assignments.errors import Conflict
from free_claude_code.assignments.models import Approval
from free_claude_code.assignments.redact import redact_value


class StateStore:
    """Append-only journal plus the latest status for each task."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Lock()

    def record(self, task_key: str, event: dict[str, Any]) -> dict[str, Any]:
        safe = redact_value({"task_key": task_key, **event})
        if not isinstance(safe, dict):
            raise Conflict("status event was not an object")
        slug = hashlib.sha256(task_key.encode("utf-8")).hexdigest()[:24]
        with self._thread:
            journal = self.root / "events.jsonl"
            with journal.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(safe, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            status_path = self.root / "status" / f"{slug}.json"
            status_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = status_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(safe, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, status_path)
        return safe

    def read_status(self, task_key: str) -> dict[str, Any] | None:
        slug = hashlib.sha256(task_key.encode("utf-8")).hexdigest()[:24]
        path = self.root / "status" / f"{slug}.json"
        if not path.is_file():
            return None
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return None
        return loaded

    @contextmanager
    def exclusive(self, task_key: str) -> Iterator[None]:
        """Hold an exclusive file lock for one task revision."""

        slug = hashlib.sha256(task_key.encode("utf-8")).hexdigest()[:24]
        lock_dir = self.root / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        path = lock_dir / f"{slug}.lock"
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise Conflict("another handoff already holds this assignment") from exc
        try:
            yield
        finally:
            os.close(fd)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def save_approval(self, approval: Approval) -> None:
        path = self._approval_path(approval.manifest_id, approval.phase)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "base_sha": approval.base_sha,
            "issue_revision": approval.issue_revision,
            "manifest_id": approval.manifest_id,
            "operator_id": approval.operator_id,
            "phase": approval.phase,
            "scope_fingerprint": approval.scope_fingerprint,
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    def get_approval(self, manifest_id: str, phase: str) -> Approval | None:
        path = self._approval_path(manifest_id, phase)
        if not path.is_file():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return Approval(
            manifest_id=str(payload["manifest_id"]),
            phase=payload["phase"],
            operator_id=str(payload["operator_id"]),
            issue_revision=str(payload["issue_revision"]),
            base_sha=str(payload["base_sha"]),
            scope_fingerprint=str(payload["scope_fingerprint"]),
        )

    def revoke(self, manifest_id: str) -> None:
        for phase in ("execute", "publish"):
            path = self._approval_path(manifest_id, phase)
            if path.is_file():
                path.unlink()

    def _approval_path(self, manifest_id: str, phase: str) -> Path:
        safe_id = hashlib.sha256(manifest_id.encode("utf-8")).hexdigest()[:24]
        return self.root / "approvals" / f"{safe_id}-{phase}.json"

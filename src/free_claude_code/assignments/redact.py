# SPDX-License-Identifier: AGPL-3.0-only
"""Redact credential-shaped strings before they reach status files or errors."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

_PATTERNS = (
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"nvapi-[A-Za-z0-9_-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"xox[bpasr]-[A-Za-z0-9-]{8,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*\S+"),
)

_REPLACEMENT = "[redacted]"


def redact(text: str) -> str:
    """Return text with credential-shaped substrings replaced."""

    cleaned = text
    for pattern in _PATTERNS:
        cleaned = pattern.sub(_REPLACEMENT, cleaned)
    return cleaned


def redact_value(value: Any) -> Any:
    """Redact strings inside JSON-like structures. Other types pass through."""

    if isinstance(value, str):
        return redact(value)
    if isinstance(value, Mapping):
        return {str(key): redact_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact_value(item) for item in value]
    return value

# SPDX-License-Identifier: AGPL-3.0-only
"""Relative path rules for scope and patches. Issue text cannot widen these."""

from pathlib import Path

from free_claude_code.assignments.errors import ScopeError

_FORBIDDEN_PREFIXES = (".github/workflows/", ".github/workflows")
_FORBIDDEN_EXACT = frozenset({"LICENSE"})


def safe_relative(value: str) -> str:
    """Return a posix relative path or raise ScopeError."""

    if not isinstance(value, str) or value == "" or "\x00" in value:
        raise ScopeError("path is empty or contains a null")
    if value.startswith(("/", "\\")) or "\\" in value or ":" in value:
        raise ScopeError("absolute or non-posix paths are not allowed")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ScopeError("path traversal is not allowed")
    return "/".join(parts)


def is_forbidden_repo_path(relative: str) -> bool:
    """Workflow files and the project license are outside assignment scope."""

    if relative in _FORBIDDEN_EXACT:
        return True
    return relative == ".github/workflows" or relative.startswith(".github/workflows/")


def path_allowed(relative: str, prefixes: tuple[str, ...]) -> bool:
    """True when the path is under an operator-configured prefix."""

    safe = safe_relative(relative)
    if is_forbidden_repo_path(safe):
        return False
    return any(safe == prefix or safe.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def contained(root: Path, candidate: Path) -> Path:
    """Resolve candidate and require it to stay inside root."""

    root_resolved = root.resolve()
    target = candidate if candidate.is_absolute() else root / candidate
    resolved = target.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ScopeError("path escapes the artifact root") from exc
    return resolved

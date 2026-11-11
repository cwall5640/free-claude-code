# SPDX-License-Identifier: AGPL-3.0-only
"""Failures for the assignment handoff. Messages must stay secret-free."""


class AssignmentError(Exception):
    """Base error. Subclasses identify the gate that refused the operation."""

    code = "assignment_error"


class Disabled(AssignmentError):
    code = "disabled"


class Forbidden(AssignmentError):
    code = "forbidden"


class ApprovalInvalid(AssignmentError):
    code = "approval_invalid"


class Conflict(AssignmentError):
    code = "conflict"


class ScopeError(AssignmentError):
    code = "scope"


class TimedOut(AssignmentError):
    code = "timed_out"


class Cancelled(AssignmentError):
    code = "cancelled"


class PublicationBlocked(AssignmentError):
    code = "publication_blocked"


class ModelSessionFailed(AssignmentError):
    """The model session ended abnormally (FCC #30).

    Carries the session's exit code and redacted output tails as evidence,
    the way a sandbox TimedOut carries the killed command's partial output
    (FCC #20): the caller recording the stop must not lose what the session
    printed before it died.
    """

    code = "model_session_failed"

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stdout_tail: str = "",
        stderr_tail: str = "",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout_tail = stdout_tail
        self.stderr_tail = stderr_tail


class MergeRejected(Forbidden):
    """Merge is not a method the worker is allowed to call."""

    code = "merge_rejected"

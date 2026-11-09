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


class MergeRejected(Forbidden):
    """Merge is not a method the worker is allowed to call."""

    code = "merge_rejected"

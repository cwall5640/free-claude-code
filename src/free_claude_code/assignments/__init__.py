# SPDX-License-Identifier: AGPL-3.0-only
"""Gated GitHub assignment sandbox. Not an unattended dev worker.

Disabled until a local config enables it. Issue text is data. Local operators
approve an exact issue revision and base SHA, then native approvals name the
exact commands that may run. The publisher can open a review pull request only
and has no merge method. NVIDIA Claude Code does not spawn unless a separate
model grant names the same task and repository.
"""

from free_claude_code.assignments.errors import (
    ApprovalInvalid,
    AssignmentError,
    Cancelled,
    Conflict,
    Disabled,
    Forbidden,
    PublicationBlocked,
    ScopeError,
    TimedOut,
)
from free_claude_code.assignments.models import (
    SOURCE_PIN,
    AllowlistEntry,
    AssignmentConfig,
    PublicationPlan,
    TaskManifest,
)
from free_claude_code.assignments.service import AssignmentService

__all__ = [
    "SOURCE_PIN",
    "AllowlistEntry",
    "ApprovalInvalid",
    "AssignmentConfig",
    "AssignmentError",
    "AssignmentService",
    "Cancelled",
    "Conflict",
    "Disabled",
    "Forbidden",
    "PublicationBlocked",
    "PublicationPlan",
    "ScopeError",
    "TaskManifest",
    "TimedOut",
]

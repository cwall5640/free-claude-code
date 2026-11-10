# SPDX-License-Identifier: AGPL-3.0-only
"""Manager-side grant signer. Worker modules do not import this module.

Run it only on the manager machine:

    python -m free_claude_code.assignments.grant_sign --key-file <path> \
        --manifest-id <id> --repo <owner/repo> --base-sha <sha> \
        --issue-revision <rev> --expires-at <unix> --out <path>

The grant key is read from that file (a single line of text, the same value
the worker holds as the grant_key secret). It is never an argument and never
printed. The signed grant is written as a private file in the exact format
the operator lane writes, ready to be placed in the worker's grants
directory as <manifest_id>.json.
"""

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.grants import ModelGrant, sign_grant
from free_claude_code.assignments.private_io import write_private_bytes


def _load_key(path: Path) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise Forbidden("grant key file must be a regular file")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600:
        raise Forbidden("grant key file must have mode 0600")
    key = path.read_text(encoding="utf-8").strip()
    if not key:
        raise Forbidden("grant key file is empty")
    return key


def _grant_dict(grant: ModelGrant) -> dict[str, object]:
    return {
        "actions": list(grant.actions),
        "base_sha": grant.base_sha,
        "expires_at": grant.expires_at,
        "issue_revision": grant.issue_revision,
        "manifest_id": grant.manifest_id,
        "repo": grant.repo,
        "signature": grant.signature,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="grant_sign")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--manifest-id", required=True)
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--issue-revision", required=True)
    parser.add_argument("--expires-at", required=True, type=int)
    parser.add_argument("--actions", default="implement",
                        help="comma-separated grant actions (default: implement)")
    parser.add_argument("--out", required=True)
    parsed = parser.parse_args(argv)
    if "/" not in parsed.repo:
        raise Forbidden("repo must be owner/repo")
    actions = tuple(item.strip() for item in parsed.actions.split(",") if item.strip())
    if not actions:
        raise Forbidden("grant needs at least one action")
    key = _load_key(Path(parsed.key_file))
    try:
        grant = sign_grant(
            key,
            ModelGrant(
                manifest_id=parsed.manifest_id,
                repo=parsed.repo,
                base_sha=parsed.base_sha,
                issue_revision=parsed.issue_revision,
                expires_at=parsed.expires_at,
                actions=actions,
                signature="",
            ),
        )
    finally:
        del key
    payload = (json.dumps(_grant_dict(grant), sort_keys=True) + "\n").encode("utf-8")
    write_private_bytes(Path(parsed.out), payload)
    print(json.dumps({"grant_written": parsed.out, "manifest_id": grant.manifest_id}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

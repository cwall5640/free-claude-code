# SPDX-License-Identifier: AGPL-3.0-only
"""Manager-side signer. Worker modules do not import this module.

Run it only on the manager machine:

    python -m free_claude_code.assignments.manager_sign --key-file <path> ...

The private key is read from that file. It is never an argument and never
printed. The worker process has no import of this module and cannot call it.
"""

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.handoff import actor_label
from free_claude_code.assignments.workflow import ManagerAttestation, _canonical, _comment_payload

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TASK = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        parsed = _parser().parse_args(args)
        secret = _read_private_key(Path(parsed.key_file))
        try:
            if parsed.next_actor:
                text = _signed_next(secret, parsed.next_actor, parsed.head or parsed.base_sha)
            else:
                text = _signed_attestation(secret, parsed)
        finally:
            del secret
    except Forbidden as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(text)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m free_claude_code.assignments.manager_sign")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--repo", default="")
    parser.add_argument("--issue", type=int, default=0)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--role", default="")
    parser.add_argument("--audience", default="")
    parser.add_argument("--issue-node-id", default="")
    parser.add_argument("--base-branch", default="")
    parser.add_argument("--updated-at", default="")
    parser.add_argument("--task-id", default="")
    parser.add_argument("--nonce", default="")
    parser.add_argument("--expires-at", type=int, default=0)
    parser.add_argument("--decision", default="assign")
    parser.add_argument("--next-actor", default="")
    parser.add_argument("--head", default="")
    return parser


def _signed_attestation(secret: bytes, parsed: argparse.Namespace) -> str:
    owner, repo = _split_repo(parsed.repo)
    if parsed.issue <= 0:
        raise Forbidden("issue number is required")
    if parsed.role not in {"vibe", "project_manager"}:
        raise Forbidden("manager role is not an assigning role")
    if parsed.decision not in {"assign", "cancel"}:
        raise Forbidden("unknown manager decision")
    if not parsed.audience or parsed.audience == parsed.principal:
        raise Forbidden("audience must name the worker and not the manager")
    if not _SHA.fullmatch(parsed.base_sha):
        raise Forbidden("base SHA must be 40 hex characters")
    if not _TASK.fullmatch(parsed.task_id):
        raise Forbidden("task id must be lowercase")
    for name, value in (
        ("issue node id", parsed.issue_node_id),
        ("base branch", parsed.base_branch),
        ("updated at", parsed.updated_at),
        ("nonce", parsed.nonce),
        ("principal", parsed.principal),
    ):
        if not str(value).strip() or "\n" in str(value):
            raise Forbidden(f"{name} is required")
    if parsed.expires_at <= 0:
        raise Forbidden("expires-at is required")
    attestation = ManagerAttestation(
        principal_id=parsed.principal,
        role=parsed.role,
        audience=parsed.audience,
        owner=owner,
        repo=repo,
        issue_number=parsed.issue,
        issue_node_id=parsed.issue_node_id,
        base_branch=parsed.base_branch,
        base_sha=parsed.base_sha,
        updated_at=parsed.updated_at,
        task_id=parsed.task_id,
        nonce=parsed.nonce,
        expires_at=parsed.expires_at,
        decision=parsed.decision,
        signature="",
    )
    signature = _sign(secret, _canonical(attestation.signed_body()))
    payload = attestation.signed_body() | {"signature": signature}
    return _public_text(secret, json.dumps(payload, sort_keys=True))


def _signed_next(secret: bytes, actor: str, head: str) -> str:
    actor_label(actor)
    if not _SHA.fullmatch(head):
        raise Forbidden("head SHA must be 40 hex characters")
    body = f"NEXT: {actor}\nHEAD: {head}\n"
    signature = _sign(secret, _comment_payload(body))
    return _public_text(secret, body + f"SIGNATURE: {signature}\n")


def _split_repo(repo: str) -> tuple[str, str]:
    owner, sep, name = repo.partition("/")
    if not sep or not owner or not name or "/" in name or owner.startswith("-") or name.startswith("-"):
        raise Forbidden("repo must be owner/name")
    return owner, name


def _sign(secret: bytes, payload: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    try:
        return Ed25519PrivateKey.from_private_bytes(secret).sign(payload).hex()
    except ValueError as exc:
        raise Forbidden("manager key file is not a raw Ed25519 key") from exc


def _public_text(secret: bytes, text: str) -> str:
    if secret.hex() in text:
        raise Forbidden("refusing to print manager key material")
    return text


def _read_private_key(path: Path) -> bytes:
    """Read a raw 32-byte key. Refuse a file that is not private."""

    if path.is_symlink():
        raise Forbidden("refusing a symlink for the manager key")
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only, is_reparse_point

        if is_reparse_point(path) or not file_is_current_user_only(path):
            raise Forbidden("manager key is not current-user-only")
        data = path.read_bytes()
    else:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise Forbidden("manager key file is not readable") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Forbidden("manager key file is not a regular file")
            if info.st_uid != os.getuid():
                raise Forbidden("manager key file is not owned by the current user")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise Forbidden("manager key file must be mode 0600")
            data = os.read(fd, 64)
        finally:
            os.close(fd)
    if len(data) != 32:
        raise Forbidden("manager key file is not a raw Ed25519 key")
    return data


if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-License-Identifier: AGPL-3.0-only
"""The manager signer is a separate command. The worker does not import it."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from free_claude_code.assignments.ed25519_verify import verify_ed25519
from free_claude_code.assignments.errors import ApprovalInvalid
from free_claude_code.assignments.manager_sign import main
from free_claude_code.assignments.workflow import ManagerAttestation, ManagerVerifier, _comment_payload

SHA = "a" * 40
OTHER = "b" * 40


def _key(path: Path, secret: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _secret(fill: int) -> bytes:
    return bytes((fill + index) % 256 for index in range(32))


def _args(key: Path, **overrides: object) -> list[str]:
    values: dict[str, object] = {
        "--key-file": str(key),
        "--principal": "vibe-coder",
        "--role": "vibe",
        "--audience": "worker-1",
        "--repo": "owner/name",
        "--issue": "9",
        "--issue-node-id": "NODE9",
        "--base-branch": "dev",
        "--base-sha": SHA,
        "--updated-at": "2026-11-09T00:00:00Z",
        "--task-id": "fix-add",
        "--nonce": "nonce-1",
        "--expires-at": "5000",
        "--decision": "assign",
    }
    values.update(overrides)
    args: list[str] = []
    for name, value in values.items():
        args.extend([name, str(value)])
    return args


def _run(path: Path, secret: bytes, capsys: pytest.CaptureFixture[str], **overrides: object) -> str:
    _key(path, secret)
    assert main(_args(path, **overrides)) == 0
    out, err = capsys.readouterr()
    assert secret.hex() not in out
    assert secret.hex() not in err
    return out


def _attestation(text: str) -> ManagerAttestation:
    raw = json.loads(text)
    return ManagerAttestation(
        principal_id=str(raw["principal_id"]),
        role=str(raw["role"]),
        audience=str(raw["audience"]),
        owner=str(raw["owner"]),
        repo=str(raw["repo"]),
        issue_number=int(raw["issue_number"]),
        issue_node_id=str(raw["issue_node_id"]),
        base_branch=str(raw["base_branch"]),
        base_sha=str(raw["base_sha"]),
        updated_at=str(raw["updated_at"]),
        task_id=str(raw["task_id"]),
        nonce=str(raw["nonce"]),
        expires_at=int(raw["expires_at"]),
        decision=str(raw["decision"]),
        signature=str(raw["signature"]),
    )


def _verifier(tmp: Path, public: bytes) -> ManagerVerifier:
    return ManagerVerifier(
        {"vibe-coder": public},
        roles={"vibe-coder": "vibe"},
        display_names={"vibe-coder": "Vibe Coder"},
        audience="worker-1",
        now=1_000,
        state_dir=tmp / "state",
        handoff_actors={"vibe-coder": "Casey"},
    )


def _public(secret: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_signed_attestation_round_trips_with_the_verifier(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = _secret(1)
    text = _run(tmp_path / "keys" / "ed25519.private", secret, capsys)
    attestation = _attestation(text)
    _verifier(tmp_path, _public(secret)).verify(
        attestation,
        node_id="NODE9",
        base_sha=SHA,
        owner="owner",
        repo="name",
        updated_at="2026-11-09T00:00:00Z",
    )


def test_tampered_field_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    secret = _secret(2)
    text = _run(tmp_path / "keys" / "ed25519.private", secret, capsys)
    raw = json.loads(text)
    raw["base_sha"] = OTHER
    tampered = _attestation(json.dumps(raw))
    with pytest.raises(ApprovalInvalid, match="signature"):
        _verifier(tmp_path, _public(secret)).verify(
            tampered,
            node_id="NODE9",
            base_sha=OTHER,
            owner="owner",
            repo="name",
            updated_at="2026-11-09T00:00:00Z",
        )


def test_wrong_key_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    secret = _secret(3)
    text = _run(tmp_path / "keys" / "ed25519.private", secret, capsys)
    attestation = _attestation(text)
    with pytest.raises(ApprovalInvalid, match="signature"):
        _verifier(tmp_path, _public(_secret(9))).verify(
            attestation,
            node_id="NODE9",
            base_sha=SHA,
            owner="owner",
            repo="name",
            updated_at="2026-11-09T00:00:00Z",
        )


def test_next_comment_verifies_and_loose_key_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = _secret(4)
    key = tmp_path / "keys" / "ed25519.private"
    _key(key, secret)
    assert main(["--key-file", str(key), "--principal", "vibe-coder", "--next-actor", "claude1", "--head", SHA]) == 0
    out, err = capsys.readouterr()
    assert secret.hex() not in out
    assert secret.hex() not in err
    assert out.startswith(f"NEXT: claude1\nHEAD: {SHA}\nSIGNATURE: ")
    signature = bytes.fromhex(out.split("SIGNATURE:", 1)[1].strip())
    assert verify_ed25519(_public(secret), _comment_payload(out), signature)
    loose = tmp_path / "loose.private"
    _key(loose, secret, 0o644)
    assert main(["--key-file", str(loose), "--principal", "vibe-coder", "--next-actor", "claude1", "--head", SHA]) == 2
    out, err = capsys.readouterr()
    assert secret.hex() not in out
    assert secret.hex() not in err
    assert "0600" in err


def test_worker_import_graph_does_not_load_the_signer() -> None:
    root = Path("src/free_claude_code")
    for path in root.rglob("*.py"):
        if path.name == "manager_sign.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert "assignments.manager_sign" not in text
        assert "import manager_sign" not in text
    code = (
        "import sys\n"
        "import free_claude_code.assignments\n"
        "import free_claude_code.assignments.__main__\n"
        "import free_claude_code.assignments.candidate\n"
        "import free_claude_code.assignments.cli\n"
        "import free_claude_code.assignments.execution\n"
        "import free_claude_code.assignments.publisher\n"
        "import free_claude_code.assignments.service\n"
        "import free_claude_code.assignments.slack_poster\n"
        "import free_claude_code.assignments.verdict_sign\n"
        "import free_claude_code.assignments.workflow\n"
        "assert 'free_claude_code.assignments.manager_sign' not in sys.modules\n"
    )
    completed = subprocess.run([sys.executable, "-c", code], check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr

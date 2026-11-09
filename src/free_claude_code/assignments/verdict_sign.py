# SPDX-License-Identifier: AGPL-3.0-only
"""Separate process that signs one worker verdict.

It builds the verdict payload itself. It has no manager-attestation type and
cannot mint an assignment. The private key is read from a file, not from argv.
"""

import json
import sys
from pathlib import Path

from free_claude_code.assignments.verdict import verdict_payload


def sign_verdict_file(private_key_file: Path, fields: dict[str, str]) -> str:
    payload = verdict_payload(fields)
    if not payload:
        raise ValueError("verdict fields are incomplete")
    key = private_key_file.read_bytes()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(key).sign(payload).hex()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "--config":
        print('{"ok": false, "error": "disabled", "exit_code": 2}')
        return 2
    raw = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    try:
        signature = sign_verdict_file(
            Path(str(raw["private_key_file"])),
            {
                "actor": str(raw["actor"]),
                "findings": str(raw.get("findings", "")),
                "head_sha": str(raw["head_sha"]),
                "limitations": str(raw.get("limitations", "")),
                "verdict": str(raw["verdict"]),
            },
        )
    except (OSError, ValueError, KeyError):
        print('{"ok": false, "error": "forbidden", "exit_code": 2}')
        return 2
    print(json.dumps({"ok": True, "signature": signature, "exit_code": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

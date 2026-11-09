# SPDX-License-Identifier: AGPL-3.0-only
"""Offline entrypoint for the disabled assignment candidate.

Importing this module does not start a listener, register a startup task, or
contact GitHub. `run-once` stays unavailable until a later approval enables it.
"""

import json
import sys
from pathlib import Path

from free_claude_code.assignments.workflow import candidate_command


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return candidate_command("show-contract")
    command = args[0]
    root = None
    if "--root" in args:
        root = Path(args[args.index("--root") + 1])
    config = Path(args[args.index("--config") + 1]) if "--config" in args else None
    approved_by = args[args.index("--approved-by") + 1] if "--approved-by" in args else ""
    reference = args[args.index("--approval-reference") + 1] if "--approval-reference" in args else ""
    if command == "run-once":
        if root is None or config is None:
            print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "run-once is not activated"}')
            return 2
        from free_claude_code.assignments.live import run_bounded, switches_live

        if not switches_live(root, config):
            print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "run-once is not activated"}')
            return 2
        return run_bounded(root, config)
    if command == "activate":
        if root is None or not approved_by or not reference:
            print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "activation requires approved-by and approval-reference"}')
            return 2
        from free_claude_code.assignments.activation import activate

        try:
            activate(root, approved_by, reference)
        except Exception as exc:
            from free_claude_code.assignments.errors import Forbidden

            if isinstance(exc, Forbidden):
                print(json.dumps({"ok": False, "error": "disabled", "exit_code": 2, "detail": str(exc)}))
                return 2
            raise
        print(json.dumps({"exit_code": 0, "ok": True, "activation_enabled": True}, sort_keys=True))
        return 0
    if command == "deactivate":
        if root is None or not approved_by:
            print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "deactivation requires approved-by"}')
            return 2
        from free_claude_code.assignments.activation import deactivate

        deactivate(root, approved_by)
        print(json.dumps({"activation_enabled": False, "exit_code": 0, "ok": True}, sort_keys=True))
        return 0
    if command == "logon":
        if root is None:
            print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "logon requires a state directory"}')
            return 2
        from free_claude_code.assignments.startup_task import logon_once

        return logon_once(root, config)
    return candidate_command(command, root)


if __name__ == "__main__":
    raise SystemExit(main())

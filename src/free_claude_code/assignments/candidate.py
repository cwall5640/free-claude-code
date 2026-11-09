# SPDX-License-Identifier: AGPL-3.0-only
"""Offline entrypoint for the disabled assignment candidate.

Importing this module does not start a listener, register a startup task, or
contact GitHub. `run-once` stays unavailable until a later approval enables it.
"""

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
    if command == "run-once":
        print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "run-once is not activated"}')
        return 2
    if command == "logon":
        if root is None:
            print('{"ok": false, "error": "disabled", "exit_code": 2, "detail": "logon requires a state directory"}')
            return 2
        from free_claude_code.assignments.startup_task import logon_once

        config = Path(args[args.index("--config") + 1]) if "--config" in args else None
        return logon_once(root, config)
    return candidate_command(command, root)


if __name__ == "__main__":
    raise SystemExit(main())

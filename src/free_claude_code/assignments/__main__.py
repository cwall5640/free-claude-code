# SPDX-License-Identifier: AGPL-3.0-only
"""Manager-driven entrypoint. Importing this module does not start a listener."""

from free_claude_code.assignments.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

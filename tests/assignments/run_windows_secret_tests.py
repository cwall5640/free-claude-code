# SPDX-License-Identifier: AGPL-3.0-only
"""Focused checks for a Windows machine. No network, keys, or model calls.

Run after installing the wheel with --no-deps. This file does not prove the
result when it is executed on Linux.
"""

import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden, MergeRejected
from free_claude_code.assignments.execution import COMMAND_ALLOWLIST_IS_A_SANDBOX
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.secrets import (
    load_secret_file,
    posix_mode_is_private,
    refuse_symlink_or_reparse,
    write_secret_file,
)
from free_claude_code.assignments.windows_acl import acl_is_current_user_only

DUMMY_READ = "dummy-read-not-a-real-token"
DUMMY_PUBLISH = "dummy-publish-not-a-real-token"


def attempt_symlink_rejection(link: Path, target: Path) -> str:
    """Return VALIDATED, UNVERIFIED, or FAILED_LINK_WAS_READ.

    UNVERIFIED means this OS refused to create a symlink. That does not
    prove the loader rejects one.
    """

    try:
        refuse_symlink_or_reparse(is_symlink=True, reparse=False)
    except Forbidden:
        pass
    else:
        return "FAILED_POLICY"
    try:
        link.symlink_to(target)
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        return (
            "UNVERIFIED "
            f"{type(exc).__name__} winerror={winerror} errno={exc.errno}"
        )
    try:
        load_secret_file(link)
    except Forbidden:
        return "VALIDATED"
    return "FAILED_LINK_WAS_READ"


class SecretAndHttpTests(unittest.TestCase):
    def test_policy_rejects_broad_access(self) -> None:
        self.assertFalse(COMMAND_ALLOWLIST_IS_A_SANDBOX)
        self.assertFalse(posix_mode_is_private(0o666, directory=False))
        self.assertFalse(
            acl_is_current_user_only(
                dacl_present=True,
                dacl_protected=True,
                allow_sids=("S-USER", "S-1-1-0"),
                other_ace_count=0,
                user_sid="S-USER",
            )
        )

    def test_private_secret_roundtrip_and_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "vault" / "secrets"
            write_secret_file(
                path,
                {"github_read": DUMMY_READ, "github_publish": DUMMY_PUBLISH},
            )
            loaded = load_secret_file(path)
            self.assertEqual(loaded.get("github_read"), DUMMY_READ)
            self.assertIn("redacted", repr(loaded))
            if os.name == "nt":
                from free_claude_code.assignments.windows_acl import (
                    file_is_current_user_only,
                )

                self.assertTrue(file_is_current_user_only(path))
                self.assertTrue(file_is_current_user_only(path.parent))
            else:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            loose = root / "loose"
            loose.mkdir()
            insecure = loose / "secrets"
            insecure.write_text(
                f"github_read={DUMMY_READ}\n", encoding="utf-8"
            )
            if os.name != "nt":
                os.chmod(loose, 0o755)
                os.chmod(insecure, 0o644)
            with self.assertRaises(Forbidden):
                load_secret_file(insecure)
            link = path.parent / "link"
            symlink_result = attempt_symlink_rejection(link, path)
            print(f"symlink_rejection={symlink_result}")
            self.assertNotEqual(symlink_result, "FAILED_LINK_WAS_READ")
            self.assertNotEqual(symlink_result, "FAILED_POLICY")
            if os.name != "nt":
                self.assertEqual(symlink_result, "VALIDATED")

    def test_local_http_fixture_and_no_secret_in_error(self) -> None:
        seen: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen.append(self.path)
                raw = json.dumps(
                    {
                        "number": 1,
                        "title": "t",
                        "body": DUMMY_PUBLISH,
                        "state": "open",
                        "updated_at": "t",
                        "node_id": "n",
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:  # noqa: N802
                seen.append(self.path)
                self.send_error(403)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            client = GitHubHttpClient(
                f"http://{host}:{port}", DUMMY_READ, timeout=5
            )
            issue = client.fetch_issue("example", "fixture", 1, timeout=5)
            self.assertEqual(issue.number, 1)
            self.assertNotIn(DUMMY_PUBLISH, repr(client))
            with self.assertRaises(MergeRejected):
                client._bytes(
                    "POST",
                    "/repos/example/fixture/pulls/1/merge",
                    timeout=5,
                    body=b"",
                )
            self.assertFalse(any("merge" in path for path in seen))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    print(f"python={sys.version.split()[0]} platform={sys.platform}")
    print("windows_acl_execution=" + ("native" if os.name == "nt" else "unrun"))
    result = unittest.main(verbosity=2, exit=False)
    sys.exit(0 if result.result.wasSuccessful() else 1)

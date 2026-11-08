# Assignment status and secrets

The manager CLI does not start a listener. Each command prints one JSON
object on stdout. Failures use `{"ok": false, "error": "<code>", "detail": "..."}`.
`detail` is passed through redaction. Secret values, `ghp_` / `github_pat_`
tokens, `nvapi-` keys, and bearer strings are replaced with `[redacted]`.

Durable task state is under the configured `state_dir`:

- `events.jsonl` is append-only. Each line is a redacted object with `task_key`
  and `status`.
- `status/<id>.json` is the latest event for that task.
- Status values include `fetched`, `approved_execute`, `approved_publish`,
  `approved_ci_rerun`, `invalidated`, `timed_out`, `cancelled`, `failed`,
  `handoff_ready`, and `publish_acknowledged`.
- A `PASS` verdict is local test evidence only. It is not CI success, not a
  model-call proof, and not merge approval. `merge_allowed` is always false.

`config.example.json` has `enabled: false`. It lists repositories and exact
test commands. It must not contain tokens. Tokens belong in the secret file
named by `secrets_file`, in a directory created for this purpose.

Secret names are `github_read`, `github_ci`, `github_publish`, `grant_key`,
and `proxy_auth`. They are separate. `github_publish` is sent only as the
pull-request request's Authorization header. `github_ci` is sent only on a
rerun that has its own approval. Neither is placed in a test or Claude
process environment. `proxy_auth` is copied only into the Claude process as
`ANTHROPIC_AUTH_TOKEN` for the loopback proxy.

On Linux, the secret file and its parent must be owned by the current user
and have no group or other permission bits. On Windows, mode bits are not
the check: the DACL must be protected and allow only the current user. If
that cannot be verified, the file is refused.

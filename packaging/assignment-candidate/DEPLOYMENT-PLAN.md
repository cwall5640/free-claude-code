# claude1 deployment handoff

This file is a handoff for a later person or a smaller bot. It does not turn anything on. Read it, then stop at every step that says Casey must approve. Do not invent a missing command. If a command is not written here, it is not approved.

Package files that belong with this plan:

- `packaging/assignment-candidate/windows/RUNBOOK.md`
- `packaging/assignment-candidate/windows/Invoke-AssignmentCandidate.ps1`
- `packaging/assignment-candidate/activation-rollback.json`
- `packaging/assignment-candidate/worker.example.json`
- `packaging/assignment-candidate/managers.example.json`
- `packaging/assignment-candidate/handoff-actors.example.json`

The laptop account name below is `<user>`. Substitute the real account only on that machine. Do not write the real name into git.

## 1. What claude1 is

`dev:claude1` is one laptop worker. Its bare name is `claude1`. It does CI, testing, branch work, fixes, and independent review. It does not merge.

When a later Casey approval turns a single pickup on, one cycle may:

1. Take work only from the label `waiting:claude1`, or from a signed handoff comment that says `NEXT: claude1` and names the pull request's current head SHA. Nothing else is an assignment. A label is routing, not permission.
2. Check that a manager signature matches a pinned Ed25519 public key, the issue, the repository, and the approved base SHA.
3. Work on a branch named `claude1/<lowercase-task-id>`.
4. Run the allowlisted test command. If tests fail, it may try again. It stops after two repair attempts and returns the logs.
5. Push that feature branch to `https://github.com/<owner>/<repo>.git` and open a pull request. The publish token stays in a separate process. The model and the tests never receive it.
6. Post a GitHub handoff comment that ends with the signature line `— dev:claude1`.
7. If its own Slack poster is enabled, post one Slack line with its own bot. If that post is off or fails, it still returns the same line to the assigning manager.

Hard rules, all of them:

- It never merges. A PASS is a signed comment. It is not a GitHub review approval and it cannot merge.
- It never pushes `main` or `master`. It refuses force pushes and tags.
- It never uses paid or GitHub-hosted CI. CI may run only on an approved self-hosted Windows X64 runner for that same repository. It must not use or retarget Inkbound runners.
- It does not edit GitHub workflows unless Casey has approved that exact edit.
- Two repair attempts is the maximum. A denied approval or a security refusal is not retried.
- It follows the PM-BRIEFING from anime-story-rpg pull request 546 (2026-11-08). The old `dev:*` and `status:*` label families were deleted that day. Do not search for them and do not recreate them.
- Discovery is only `waiting:claude1`, or a signed `NEXT: claude1` comment that names the pull request's current head SHA. An ordinary issue still uses the approved base SHA.
- Branches are `claude1/<task-id>` with a lowercase task id.
- Every GitHub comment ends with `— dev:claude1`. A verdict (PASS, READY, or HOLD) counts only in a signed comment that names the pull request's current head SHA.
- The Slack line, when posted, is only this shape: `HANDOFF: <task-id> | <PR URL> | <head SHA> | <PASS/HOLD/INCOMPLETE/STALE> | NEXT: <actor>`. PASS means the step is done. It does not mean approved.
- claude1 is a reviewer of record. A signed PASS at the current head can satisfy independent review, including on a Minerva pull request, because claude1 is not Minerva. claude1 never reviews a pull request it authored or pushed.
- Assigning managers are a config file, not hard-coded names. Casey decided on 2026-11-09 that the three permanent managers are Vibe Coder, Project Manager (Grok), and Minerva. None of them has `interim_until`. Minerva's key does not expire. Project Manager stays a manager. The software still honors `interim_until` on some other entry and rejects that key after that UTC day. The example file does not set the field. Removing a manager is deleting that object from the config. That is a config change, not a code change.
- Slack uses claude1's own Slack app. The only bot scope is `chat:write`. The only channel is `#all-bot-army`. It never posts as Casey and it never uses a user token.

Board rows and labels are claims. Before acting, read the live pull request head from the GitHub API.

## 2. Current status

Repository: `https://github.com/cwall5640/free-claude-code`

- Pull request 1 is the upstream import. It was still unmerged when this plan was written. Its imported base commit is `61e5d7d50acd61345a25e77c66dd3acc795b3716`.
- Pull request 2 is the assignment worker. Its git base is the branch `cursor/import-upstream-main-66df`. It is not merged.

Head history that matters, oldest first:

| Head | What it was |
| --- | --- |
| `37a797d44576811b8ec91b9cf5613040f0f45e98` | Portable secret and fixture tests. Windows ACL not yet executed. |
| `2a93a6b5` | Mock workflow. Independent review: HOLD. |
| `c3f0af40` | Real adapters, still disabled. Independent review: HOLD. |
| `36ec9f52` | Ed25519 manager checks. Independent review: HOLD. |
| `386109bc` | Per-install worker identity. `claude1` is only the example. |
| `3a68f6c4` | Disabled Slack poster. Independent review recorded as pass-for-native. |
| `7bd49f99` | Windows path and binary-file fixes. |
| `8b2aebf2` | Windows git working-directory and secret-fixture fixes. |
| `e1d196d8` | Test fixture finds `git-http-backend` from `git --exec-path`. |
| `e16b1e01` | Test-only. On Windows, `claims.json` privacy uses the ACL helper instead of POSIX mode bits. |
| `a598ec0d` | Deployment plan only. No production change. |

Confirm the pull request head on GitHub before you treat any SHA above as current. The state-file ACL fix is `5324223058e533852effdfef67e94d86c5979c46`. The permanent-manager decision follows that commit: Vibe Coder, Project Manager, and Minerva have no `interim_until`.

Native Windows checks on the laptop, disposable directories only. The original Free Claude Code install was not the test target.

| Run | Head | Pytest | Manual checks |
| --- | --- | --- | --- |
| 1 | `3a68f6c4` | 34 passed, 5 failed, 3 skipped | PASS (ShowContract, Install, Activate, RunOnce, no new scheduled task, power scheme unchanged, DACL, reparse root, pid probe) |
| 2 | `7bd49f99` | 38 passed, 5 failed, 0 skipped | PASS. Secret unittest 3/3 OK, junction reparse validated. |
| 3 | `8b2aebf2` | 40 passed, 3 failed, 0 skipped | Security, DACL, reparse, and PowerShell tests passed. Three failures were git checkout working directory and secret-folder ACL fixtures. |
| 4 | `e1d196d8` | 42 passed, 1 failed, 0 skipped | PASS. Secret unittest 3/3 OK with native ACL. The one failure was `claims.json` mode bits `33206` (`0o100666`). NTFS privacy is the DACL, not those bits. |
| 5 | `a598ec0d` | 42 passed, 1 failed, 0 skipped | PASS. Secret unittest 3/3 OK. `claims.json` is not current-user-only. The file was created with the inherited DACL. Mode `0o600` does not change that on Windows. |

`e16b1e01` only changed the test. Run 5 showed the production gap: claims, and the same write path for the other state files, never called `harden_path`. The following commit hardens every state write (claims, queue, locks, integrity keys, nonces, startup plan, service journal, status, approvals, handoff artifacts, grant files, Slack `posted.txt`, and the publisher askpass token). The temp file is hardened before `os.replace`, and the destination is hardened after. POSIX mode is `0o600` for files and `0o700` for state directories.

Linux rerun of that fix, Python 3.14.10: 41 passed, 3 skipped. The three skips are still the Windows-only DACL, junction, and PowerShell tests. The new state-file privacy test ran on Linux and checked mode bits. The Windows secret script printed `windows_acl_execution=unrun` and `symlink_rejection=VALIDATED`. Nobody has rerun native Windows pytest on the ACL fix yet. Do that before merge. Do not call the Linux run a Windows pass.

Linux command used for the counts above:

```text
PYTHONPATH=src python3.14 -m pytest tests/assignments/test_automatic_workflow.py tests/assignments/test_slack_poster.py tests/assignments/test_assignment_sandbox.py tests/assignments/test_http_adapters.py --noconftest -o addopts=''
```

Separate Linux secret script: 3 tests OK.

```text
PYTHONPATH=src python3.14 tests/assignments/run_windows_secret_tests.py
```

Everything in this package is still disabled. `activation-rollback.json` has `"executed": false`. Nothing has been activated, posted, or merged by this worker.

## 3. Deployment steps

Do these in order. Each gated step needs Casey's explicit OK before it starts. A chat message that is not that OK is not approval.

Rollback for every step that touches a disposable directory: follow `activation-rollback.json` and `windows/RUNBOOK.md`. Delete only the disposable root passed to Install. Leave the original Free Claude Code install, the Inkbound runners, and the pilot repository untouched. If a GitHub or Slack step is wrong, disable the flag you turned on and remove only the credential you added. Do not rotate or print unrelated credentials.

### Step 1. Final review of one exact head

Who approves: an independent reviewer, then Casey.

Command: on GitHub, open pull request 2 and read the head SHA. It must be the SHA you intend to ship. Do not review an older SHA from this document if the pull request has moved.

Verify: the review comment is signed, names that exact head SHA, and says what was and was not run. A Windows rerun of the state-file ACL fix (the commit after `a598ec0d`) is still required. Record pass, fail, and skip counts.

Rollback: do not merge. Leave the pull request open.

### Step 2. Merge pull request 2, and decide pull request 1

Who approves: Casey. Merging is a human action. claude1 does not merge.

Pull request 2 merges into `cursor/import-upstream-main-66df` only after step 1 passes on that exact head. Do not push or merge `main` as part of this.

Pull request 1 is the upstream import. Merging it to `main` is a separate decision. Casey has not made that decision in the sources for this plan. Do not merge pull request 1 just because pull request 2 merged. Do not change the default branch.

Verify: pull request 2 shows merged, and `main` is unchanged unless Casey separately approved a `main` merge.

Rollback: use GitHub's revert of the merge commit Casey identifies. Do not force-push. Do not delete the branch until Casey says so.

### Step 3. Manager keys

Who approves: Casey, and each manager who will hold a private key.

Generate one Ed25519 key pair per manager on a machine that manager controls. Pin only the public key into the manager config. The example file is `packaging/assignment-candidate/managers.example.json`. Copy it to a private config path that is not committed. Replace every example public key. The example keys in git are placeholders. They are not the live keys.

The worker verifies public keys. It has no function that signs a manager assignment. Do not put a private key in the worker tree, in git, in Slack, or in a prompt.

Fields that matter: `principal_id`, `role` (`vibe` or `project_manager`), `display_name`, `github_login`, `handoff_actor`, and `public_key_hex`. Do not set `interim_until` on Vibe Coder, Project Manager, or Minerva. Map Vibe Coder's handoff actor to Casey (`waiting:casey`), Project Manager to Grok (`waiting:grok`), and Minerva to Minerva (`waiting:minerva`). Those labels are the legal set in `handoff-actors.example.json`, plus a `claudeN` worker.

Verify: a signature from each pinned key is accepted, and a removed key is rejected. A synthetic entry that sets `interim_until` is rejected when the worker clock is after that UTC day. Use a disposable clock in a test. Do not change the laptop clock, and do not put an expiry on the three permanent managers.

Rollback: remove that manager's object from the private config and restart nothing until Casey says the file is correct. Delete any private key file that was written in the wrong place. Do not commit the replacement file if it contains a private key.

### Step 4. Publisher GitHub access

Who approves: Casey. This decision is still open.

The publisher reads a secret named `github_publish` from the private secret file. It pushes only `claude1/<task-id>` to `https://github.com/<owner>/<repo>.git`. It refuses `main`, `master`, force pushes, and tags. The token is not an argument and not visible to the model or the tests.

Open decision, do not close it yourself: which existing GitHub credential, if any, may be placed in `github_publish`. Do not create a new personal access token. Do not expand scopes. Do not assume a repo-admin login is allowed to merge just because it can push. A login that can merge is a bad publisher credential unless Casey explicitly accepts that risk in writing.

Verify: with the publisher still disabled, confirm the secret file is mode-private on Linux or ACL-private on Windows, the value is not in the environment, and a refused push (main, force, tag, wrong host) fails closed. Do not push to a live repository during this check unless Casey named that one push.

Rollback: delete the `github_publish` line from the secret file. Leave other secrets in place. Do not print the file.

### Step 5. claude1 Slack app

Who approves: Casey creates the app. The bot must not be Casey's user.

Create one Slack app named `claude1`. Bot token scope is only `chat:write`. Invite that bot only to `#all-bot-army`. Put the channel id in `slack_channel_id` in the worker identity file. Put the bot token in the private secret file under the name `slack_bot`. The token must start with `xoxb-`. Refuse a user token (`xoxp-`). Leave `slack_enabled` false until step 7.

Identity file shape is `worker.example.json`. Copy it. Do not commit the copy if it contains a channel id you were told to keep private, and never commit the token.

Verify: `slack_enabled` is still false. A disabled run returns the HANDOFF line and does not call Slack. The RUNBOOK section is the operator text.

Rollback: revoke the Slack app token in Slack's settings and remove `slack_bot` from the secret file. Do not paste the token into chat or git.

### Step 6. Startup and plugged-in wake

Who approves: Casey. The current package does not do this.

Intended behavior, not built as a live switch: start only after Windows sign-in, and stay awake only when the session is active, the machine is plugged in, and the network is online. Otherwise queue the work. Do not change the power scheme.

What the package does today: Install writes `startup-plan.json` with `enabled` false and `registered_with_os` false. Activate and RunOnce exit 2. `activation-rollback.json` says not to register a sign-in task and not to change power settings.

Disposable check, from `windows/RUNBOOK.md`. Use a new empty directory. Do not point `-Root` at `FreeClaudeCode`, `fcc-pilot-runner-20261108`, Inkbound, or a coding-trial task.

```powershell
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode ShowContract -Root .\scratch -Python C:\Users\<user>\AppData\Local\Programs\Python\Python314\python.exe -SourceRoot C:\path\to\repo\src
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode Install -Root .\scratch -Python C:\Users\<user>\AppData\Local\Programs\Python\Python314\python.exe -SourceRoot C:\path\to\repo\src
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode Activate -Root .\scratch
```

Verify: ShowContract exits 0 only when Python and SourceRoot are set, and the contract says activation is disabled. ShowContract without Python and SourceRoot exits 2. Install exits 0 and the plan file has `enabled` false and `registered_with_os` false. Activate exits 2. Scheduled tasks and the power scheme are unchanged.

Rollback: delete only that scratch directory. See `activation-rollback.json`.

Do not create a sign-in scheduled task in this step. A later build must gain Casey's OK before any task is registered, and this document has no registration command on purpose.

### Step 7. Flip the live switch

Who approves: Casey, after steps 1 through 6.

The entry point `python -m free_claude_code.assignments.candidate run-once` still exits 2. There is no hidden flag in this package that makes it live. Flipping the switch means a later reviewed change that Casey has approved, then setting the candidate `enabled` flag and `slack_enabled` in the private identity file. Do not flip either flag while `run-once` still returns 2.

Verify: one read of the contract still shows the hard rules. A process list shows no new listener until that later build is the one Casey approved.

Rollback: set `enabled` and `slack_enabled` back to false. Do not unregister Inkbound or the original Free Claude Code server.

### Step 8. One supervised test task

Who approves: Casey names the repository, the issue, and the manager. One task only.

Use a disposable working directory. Do not use the original Free Claude Code home. The assigning manager signs the assignment. claude1 may open a feature branch and a pull request. A human reviews it. Nobody merges it in this step unless Casey gives a separate merge OK, and claude1 still does not merge.

Verify: the branch is `claude1/<task-id>`, the pull request is not targeting a push of `main`, the comment ends with `— dev:claude1`, the head SHA in the comment matches the live head, and repair attempts are at most two. CI, if any, is the approved local runner only.

Rollback: close the pull request without merging. Delete the feature branch only if Casey says to. Do not reset `main`.

### Step 9. Announce in #all-bot-army

Who approves: Casey, after step 8 looks right.

Post one HANDOFF line with the claude1 bot, or have the assigning manager post the line the worker returned. Use the exact format in section 1. Do not add a second paragraph. Do not post as Casey.

Verify: one message, right channel, right bot name.

Rollback: a human deletes that one Slack message in Slack. The bot is not allowed to delete messages.

## 4. Adding claude2 and claude3

Each extra laptop gets its own copy of the identity file. Start from `worker.example.json`. Change only that install's file:

| Field | claude1 example | Another laptop |
| --- | --- | --- |
| `actor_name` | `dev:claude1` | `dev:claude2` or `dev:claude3` |
| `bare_name` | `claude1` | `claude2` or `claude3` |
| `branch_prefix` | `claude1` | the same bare name |
| `comment_signature` | `— dev:claude1` | `— dev:` plus the actor name |
| `waiting_label` | `waiting:claude1` | `waiting:` plus the bare name |
| `github_login` | the account that pushes | that laptop's publisher account |
| `verdict_key_file` | path to that worker's verdict key | a different key file |
| `slack_enabled` | `false` until Casey says otherwise | `false` until Casey says otherwise |
| `slack_channel_id` | the `#all-bot-army` channel id | the same channel id, the worker's own bot |

Each laptop gets its own Slack app, named for that worker, with only `chat:write`, invited only to `#all-bot-army`, and its own `slack_bot` secret. They do not share Casey's user token and they do not share each other's bot token.

A new `waiting:claude2` or `waiting:claude3` label is not allowed until the PM-BRIEFING is updated and Casey approves that update. The briefing that exists today names `waiting:claude1` only. Do not create the label first and document it later.

claude2 may review claude1's pull requests. claude1 may review claude2's. A worker still refuses a pull request it authored or pushed.

## 5. Things to preserve

Do not install over, reconfigure, restart, or point `-Root` at any of these:

- The original Free Claude Code install: `C:\Users\<user>\AppData\Local\Programs\FreeClaudeCode`. Its proxy listens on `127.0.0.1:8082` only. NVIDIA is already configured there. The intended model id is `nvidia_nim/nvidia/nemotron-3-ultra-550b-a55b`. Leave that config and its keys alone.
- The Inkbound RPG self-hosted runners and the RPG listener. They are a different project. Idle is not permission to use them.
- The pilot runner directory `C:\Users\<user>\fcc-pilot-runner-20261108` and the private pilot repository `cwall5640/fcc-worker-pilot`. That pilot proved one supervised toy edit and one local CI pass. It is not this worker.

Before and after any disposable test, check the original proxy with a read-only health request to `http://127.0.0.1:8082`. Expect HTTP 200. Do not send a model prompt as part of deployment.

## 6. Safety

- Casey's explicit OK is required before merge, key pinning, publisher credentials, Slack token storage, startup registration, power changes, enabling the worker, the live test task, and the announcement.
- Never retry a denied approval or a security refusal.
- Never print, log, paste, or commit a token, a private key, a secret file, or the contents of the original Free Claude Code home.
- Never commit `slack_bot`, `github_publish`, or a private Ed25519 key.
- POSIX `chmod` is not proof of privacy on Windows. Use the DACL check.
- If you do not know the command, stop. Do not guess a scheduled-task command, a merge command, or a new token.

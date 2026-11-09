# claude1 deployment handoff

This file is a handoff for a later person or a smaller bot, including Minerva. It is enough to deploy `claude1`, `claude2`, or `claude3` on a new Windows machine. It does not turn anything on. Read section 7 before touching a machine. Stop at every step marked **Casey's OK**. Do not invent a missing command. If a command is not written here, it is not approved.

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

What happened on 2026-11-09:

- Pull request 2 merged into pull request 1. Pull request 1 was the import branch `cursor/import-upstream-main-66df`.
- Before pull request 1 merged to `main`, the hosted-runner workflows were removed: `.github/workflows/post-merge.yml` (push to `main` on hosted Ubuntu, Windows, and macOS, plus a PyPI publish) and `.github/workflows/validate-bug-report-version.yml` (hosted Ubuntu on new or edited issues). That removal is commit `a2fff668f578b336543325a92bf37e00aad58afc`. There is no paid CI on `main`.
- `.github/dependabot.yml` was left in place. Do not delete it without **Casey's OK**.
- Pull request 1 then merged to `main`. The merge commit is `f74f1392dd32a196688c7b705b6022e8af7c945b`.
- The worker is still disabled. `activation-rollback.json` has `"executed": false`. Nothing has been activated or posted by this worker.

`main` at `f74f1392` does not yet contain the manager signing command. That command is the change that carries this plan. Clone `main` for a new machine only after that change is on `main`. Until then, stop. Merging it needs **Casey's OK**. claude1 does not merge.

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

Linux rerun of that fix, Python 3.14.10: 41 passed, 3 skipped. The three skips are still the Windows-only DACL, junction, and PowerShell tests. The new state-file privacy test ran on Linux and checked mode bits. The Windows secret script printed `windows_acl_execution=unrun` and `symlink_rejection=VALIDATED`. The merge to `main` did not include a later native Windows pass of the ACL fix. A new machine must pass the validation in section 7 before it is trusted. Do not call a Linux run a Windows pass.

Linux command used for the counts above:

```text
PYTHONPATH=src python3.14 -m pytest tests/assignments/test_automatic_workflow.py tests/assignments/test_slack_poster.py tests/assignments/test_assignment_sandbox.py tests/assignments/test_http_adapters.py --noconftest -o addopts=''
```

Separate Linux secret script: 3 tests OK.

```text
PYTHONPATH=src python3.14 tests/assignments/run_windows_secret_tests.py
```

## 3. Deployment steps

Do these in order. Each gated step needs Casey's explicit OK before it starts. A chat message that is not that OK is not approval.

Rollback for every step that touches a disposable directory: follow `activation-rollback.json` and `windows/RUNBOOK.md`. Delete only the disposable root passed to Install. Leave the original Free Claude Code install, the Inkbound runners, and the pilot repository untouched. If a GitHub or Slack step is wrong, disable the flag you turned on and remove only the credential you added. Do not rotate or print unrelated credentials.

### Step 1. Final review of one exact head

Status: done for the import. Pull request 2 was reviewed and merged into pull request 1. A new machine still runs the native validation in section 7. That validation is not a merge.

### Step 2. Merge pull request 2, and decide pull request 1

Status: done. Pull request 2 merged into pull request 1. Pull request 1 merged to `main` at `f74f1392dd32a196688c7b705b6022e8af7c945b` after the hosted workflows were removed. Dependabot remains. Later merges still need **Casey's OK**. claude1 does not merge.

Rollback, if Casey asks: revert the merge commit Casey names. Do not force-push. Do not delete a branch until Casey says so.

### Step 3. Manager keys

Status: done for the first three managers. **Casey's OK** is required before adding another principal or copying a private key anywhere else.

The three private keys are on the shared bot computer, one directory per principal:

- `/home/box/agent-data/claude1-manager-keys/vibe-coder/ed25519.private`
- `/home/box/agent-data/claude1-manager-keys/project-manager/ed25519.private`
- `/home/box/agent-data/claude1-manager-keys/minerva/ed25519.private`

Each directory is mode `0700`. Each private file is raw 32 bytes and mode `0600`. The principals are Vibe Coder (`vibe`, handoff actor Casey), Project Manager (`project_manager`, handoff actor Grok), and Minerva (`project_manager`, handoff actor Minerva). None of them has `interim_until`.

Caveat: those three keys share one computer. They are not on three separate manager machines. A person or bot that can read that computer can use all three keys. Do not describe this as separate custody. Do not copy a private key to a laptop, into git, into Slack, or into a prompt.

The laptop has only the public keys, staged at `C:\Users\<user>\claude1-worker-config\managers.json`. That file is public keys only. Its ACL is current-user-only. The example file `packaging/assignment-candidate/managers.example.json` is a shape, not the live keys. Do not commit the staged file.

The worker verifies public keys. It does not import the manager signer. A manager signs on the bot computer:

```text
python -m free_claude_code.assignments.manager_sign --key-file /home/box/agent-data/claude1-manager-keys/<principal>/ed25519.private --principal <principal> --role <vibe|project_manager> --audience <worker-audience> --repo <owner>/<name> --issue <N> --issue-node-id <node> --base-branch <branch> --base-sha <40 hex> --updated-at <timestamp> --task-id <lowercase-task-id> --nonce <unique> --expires-at <unix> --decision assign
```

`<worker-audience>` is the audience configured for that worker. It must not be the principal id. Vibe Coder uses `--role vibe` and `--principal vibe-coder`. Project Manager uses `--role project_manager` and `--principal project-manager`. Minerva uses `--role project_manager` and `--principal minerva`. Add `--next-actor claude1 --head <40 hex pull head>` to print a signed NEXT comment instead of the attestation. For claude2 or claude3, use that bare name as `--next-actor` only after the label step in section 7. The worker and the model process must not run this module.

Verify: a signature from each pinned public key is accepted, and a removed key is rejected. Do not print the private file.

Rollback: remove that manager's object from `managers.json` on the laptop. Leave the private key in place until Casey says to delete that one file. Do not commit either file.

### Step 4. Publisher GitHub access

**Casey's OK** for every token. One token per worker. Do not reuse Casey's token and do not reuse another worker's token.

Casey creates a fine-grained personal access token in GitHub's settings:

- Token name: `claude1-publisher`, `claude2-publisher`, or `claude3-publisher`, matching that worker.
- Expiration: 90 days.
- Repository access: only selected repositories. Not all repositories.
- Permissions: Contents read and write, Pull requests read and write. Every other permission is none.
- Casey puts the token into the secure secret form. Never paste it into chat, a prompt, a log, or git.

Store it on that worker's laptop as the name `github_publish` in the worker secret file next to the public manager file: `C:\Users\<user>\claude1-worker-config\` holds `managers.json` and the secret file beside it. The secret file ACL is current-user-only. The publisher reads `github_publish` from that file. It pushes only `claudeN/<task-id>` to `https://github.com/<owner>/<repo>.git`. It refuses `main`, `master`, force pushes, and tags. The token is not an argument and is not visible to the model or the tests.

Also ask Casey to turn on a `main` branch rule that requires a pull request review before merge. The token can push a feature branch and open a pull request. The branch rule is what stops that token from merging to `main`. Do not skip the rule because the worker also refuses to push `main`.

Verify: the publisher is still disabled. The secret file is current-user-only. The value is not in the environment. A refused push (`main`, force, tag, or wrong host) fails closed. Do not push to a live repository during this check unless Casey named that one push. Do not print the file.

Rollback: delete the `github_publish` line from the secret file and revoke that token in GitHub. Leave other secrets in place. Do not print the file.

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

- Casey's explicit OK is required before a new-machine install, a publisher token, Slack token storage, a new `waiting:claudeN` label, startup registration, power changes, enabling the worker, the live test task, the announcement, and any later merge.
- A publisher token arrives through the secure secret form. Never through chat.
- Never retry a denied approval or a security refusal.
- Never print, log, paste, or commit a token, a private key, a secret file, or the contents of the original Free Claude Code home.
- Never commit `slack_bot`, `github_publish`, or a private Ed25519 key.
- POSIX `chmod` is not proof of privacy on Windows. Use the DACL check.
- If you do not know the command, stop. Do not guess a scheduled-task command, a merge command, or a new token.

## 7. New machine checklist

Do these in order for each new Windows machine. The laptop account is `<user>`. Write the real account only on that machine. `N` is `1`, `2`, or `3`.

1. **Casey's OK.** Name the machine and the worker (`claude1`, `claude2`, or `claude3`). Do not use an Inkbound machine. Do not reuse the pilot runner directory.
2. **Casey's OK** before the first Free Claude Code install on that machine. Use the free-claude-code-nvidia-setup flow. In plain terms: install Free Claude Code for that Windows user, point it at NVIDIA NIM, bind the proxy to `127.0.0.1:8082` only, and select model `nvidia_nim/nvidia/nemotron-3-ultra-550b-a55b`. Provider keys stay inside that install. Do not copy them into the worker config and do not print them. If an install already exists at `C:\Users\<user>\AppData\Local\Programs\FreeClaudeCode`, leave it. Check `http://127.0.0.1:8082` returns 200. Do not send a model prompt.
3. **Casey's OK** for the Python install if it is not the already reviewed Python 3.14. Make a disposable virtual environment for the validation run. Do not install the candidate into the Free Claude Code virtual environment.
4. Clone `https://github.com/cwall5640/free-claude-code.git` and check out `main` only after this plan is on `main`. Record the SHA. Confirm `.github/workflows/post-merge.yml` and `.github/workflows/validate-bug-report-version.yml` are absent. Leave `.github/dependabot.yml` unless Casey says otherwise.
5. Native validation must pass before any later step. From the clone, with the disposable virtual environment:
   ```text
   python -m pytest tests/assignments/test_automatic_workflow.py tests/assignments/test_slack_poster.py tests/assignments/test_assignment_sandbox.py tests/assignments/test_http_adapters.py --noconftest -o addopts=''
   python tests/assignments/run_windows_secret_tests.py
   ```
   Also run `tests/assignments/test_manager_sign_cli.py` when that file is in the clone. Then the manual checks in `windows/RUNBOOK.md`, using a new empty directory that is not the Free Claude Code install: ShowContract exits 0 with Python and SourceRoot set, ShowContract exits 2 without them, Install exits 0 with `enabled` false and `registered_with_os` false, Activate exits 2, RunOnce exits 2, no new scheduled task, the power scheme is unchanged, and the disposable root's ACL is current-user-only. The secret script must be 3/3 OK. The proxy still returns 200. A failure stops the checklist. This step does not enable the worker.
6. Write that machine's identity file from `worker.example.json`. Set `actor_name` to `dev:claudeN`, `bare_name` and `branch_prefix` to `claudeN`, `comment_signature` to `— dev:claudeN`, `waiting_label` to `waiting:claudeN`, and `github_login` to that worker's publisher account. Create a new verdict key file for this worker only, current-user-only, and put its path in `verdict_key_file`. Leave `slack_enabled` false and `slack_channel_id` empty until checklist item 9. Do not commit this file.
7. Reuse the same pinned public `managers.json` from deployment step 3. Copy the public file, not the private keys. The private keys stay on the shared bot computer.
8. **Casey's OK.** Create this worker's publisher token as in deployment step 4. Store `github_publish` in the secret file next to `managers.json`, with a current-user-only ACL. Use the secure secret form. Never chat.
9. **Casey's OK.** Create this worker's Slack app as in deployment step 5. One app, named `claudeN`, scope `chat:write` only, invited only to `#all-bot-army`, token stored as `slack_bot` in that same secret file. Leave `slack_enabled` false.
10. **Casey's OK** before any new `waiting:claudeN` label. `waiting:claude1` is already in the PM-BRIEFING. `waiting:claude2` and `waiting:claude3` need a PM-BRIEFING update that Casey approves before the label is created. Do not create the label first.
11. **Casey's OK** before startup registration, power changes, `enabled` true, `slack_enabled` true, the supervised test task, or the `#all-bot-army` announcement. Those are deployment steps 6 through 9 in section 3. The package still refuses `run-once` with exit 2. Do not invent a switch.

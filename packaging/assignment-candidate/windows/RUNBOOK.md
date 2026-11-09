# Disposable Windows candidate

Run this from a new empty directory. Do not point `-Root` at `FreeClaudeCode`, `fcc-pilot-runner-20261108`, Inkbound, or an existing coding-trial task.

`Install` calls the Python candidate, which writes `startup-plan.json` with `enabled=false` and does not register a sign-in task or change power settings. `Activate` and `RunOnce` exit 2. The process exit code is the result. Stderr text alone is not a failure.

```powershell
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode ShowContract -Root .\scratch -Python C:\Users\cwall\AppData\Local\Programs\Python\Python314\python.exe -SourceRoot C:\path\to\repo\src
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode Install -Root .\scratch -Python C:\Users\cwall\AppData\Local\Programs\Python\Python314\python.exe -SourceRoot C:\path\to\repo\src
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode Activate -Root .\scratch
```

Native PowerShell 5.1, Python 3.14.10, and Git 2.56.0 still need a parent review before any use. This package does not enable the live loop. `ShowContract` fails closed unless Python and SourceRoot actually run `show-contract`. Manager assignment is an Ed25519 signature checked with a pinned public key from the manager config. The worker package that verifies those keys cannot mint them. The em dash suffix is a text convention, not a signature. Each laptop loads its own worker identity file; claude1 is only the example. The publisher stays disabled until a later approval and pushes only to `https://github.com/<owner>/<repo>`.

Slack handoff is disabled until `slack_enabled` is true in that worker's identity file. Create one Slack app per worker and name it for that worker, such as `claude1`. The app's only bot token scope is `chat:write`. Invite that bot to `#all-bot-army` and to no other channel. Copy the channel id into `slack_channel_id`. Store the bot token, which starts with `xoxb-`, in the private secret file as `slack_bot`. Do not use a user token (`xoxp-`) and do not use Casey's user token. The poster sends one `chat.postMessage` and no edits, deletes, or file uploads. If the poster is disabled or the post fails, the HANDOFF line is returned to the assigning manager instead.

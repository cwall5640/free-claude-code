# Disposable Windows candidate

Run this from a new empty directory. Do not point `-Root` at `FreeClaudeCode`, `fcc-pilot-runner-20261108`, Inkbound, or an existing coding-trial task.

`Install` calls the Python candidate, which writes `startup-plan.json` with `enabled=false` and does not register a sign-in task or change power settings. `Activate` and `RunOnce` exit 2. The process exit code is the result. Stderr text alone is not a failure.

```powershell
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode ShowContract -Root .\scratch
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode Install -Root .\scratch -Python C:\Users\cwall\AppData\Local\Programs\Python\Python314\python.exe -SourceRoot C:\path\to\repo\src
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode Activate -Root .\scratch
```

Native PowerShell 5.1, Python 3.14.10, and Git 2.56.0 still need a parent review before any use. This package does not enable the live loop. Unattended manager trust stays blocked while verification uses a symmetric key the worker can read.

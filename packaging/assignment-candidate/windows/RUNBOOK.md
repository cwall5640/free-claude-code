# Disposable Windows candidate

This package is for a later independent review. It is not installed and it is not authorized to run on the laptop.

Use a new empty directory. Do not point it at `FreeClaudeCode`, `fcc-pilot-runner-20261108`, Inkbound, or an existing `FccCodingTrial` task.

```powershell
powershell.exe -NoProfile -NonInteractive -File .\Invoke-AssignmentCandidate.ps1 -Mode ShowContract
```

`ShowContract` exits 0. `Install` and `Activate` exit 2. The script does not change power settings, sign-in startup, Git config, or runner registration.

Native checks still required before any use: Windows PowerShell 5.1 parse and both modes, Python 3.14.10, Git 2.56.0, current-user DACL, and reparse refusal. Those were not run to produce this package. A non-zero process exit is the result. Stderr text alone is not a failure.

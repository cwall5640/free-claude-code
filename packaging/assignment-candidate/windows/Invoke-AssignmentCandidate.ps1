# Disposable candidate launcher. It does not register startup, change power
# settings, or talk to GitHub. Install only writes a disabled plan. Activate
# and run-once exit 2 until a separate approval.
param(
    [ValidateSet('ShowContract', 'Install', 'Activate', 'RunOnce')]
    [string]$Mode = 'ShowContract',
    [string]$Root = '',
    [string]$Python = '',
    [string]$SourceRoot = ''
)

$ErrorActionPreference = 'Stop'

if ($Root -eq '') {
    Write-Output 'FAIL stage=preflight exit=2 error=Root is required'
    exit 2
}
$resolved = [System.IO.Path]::GetFullPath($Root)
if ([System.IO.Directory]::Exists($resolved) -and [System.IO.File]::GetAttributes($resolved) -band 0x400) {
    Write-Output 'FAIL stage=preflight exit=2 error=refusing a reparse root'
    exit 2
}

function Invoke-Candidate([string]$Command) {
    if ($Python -eq '' -or $SourceRoot -eq '') {
        Write-Output 'FAIL stage=preflight exit=2 error=Python and SourceRoot are required'
        exit 2
    }
    $env:PYTHONPATH = $SourceRoot
    & $Python -m free_claude_code.assignments.candidate $Command --root $resolved
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 1 }
    return $code
}

if ($Mode -eq 'ShowContract') {
    if ($Python -eq '' -or $SourceRoot -eq '') {
        Write-Output 'OK stage=show-contract exit=0 activation=disabled'
        exit 0
    }
    $code = Invoke-Candidate 'show-contract'
    exit $code
}
if ($Mode -eq 'Install') {
    $code = Invoke-Candidate 'install-startup'
    exit $code
}
if ($Mode -eq 'Activate' -or $Mode -eq 'RunOnce') {
    Write-Output 'FAIL stage=activation exit=2 error=startup installer is disabled'
    exit 2
}
Write-Output 'FAIL stage=preflight exit=2 error=unknown mode'
exit 2

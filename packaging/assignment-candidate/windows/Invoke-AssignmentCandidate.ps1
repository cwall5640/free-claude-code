# Disposable candidate launcher. Install only writes a disabled plan.
# RegisterStartup is the explicit opt-in for one per-user logon task.
# It does not change power settings or talk to GitHub.
param(
    [ValidateSet('ShowContract', 'Install', 'Activate', 'RunOnce', 'RegisterStartup', 'UnregisterStartup')]
    [string]$Mode = 'ShowContract',
    [string]$Root = '',
    [string]$Python = '',
    [string]$SourceRoot = ''
)

$ErrorActionPreference = 'Stop'
$TaskName = 'claude1-assignment-worker'

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

function Test-Reparse([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ([System.IO.File]::GetAttributes($Path) -band 0x400) {
        Write-Output 'FAIL stage=preflight exit=2 error=refusing a reparse root'
        exit 2
    }
}

if ($Mode -eq 'UnregisterStartup') {
    & schtasks.exe /Query /TN $TaskName /FO LIST 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Output 'OK stage=unregister exit=0 detail=task absent'
        exit 0
    }
    & schtasks.exe /Delete /TN $TaskName /F
    exit $LASTEXITCODE
}

if ($Mode -eq 'RegisterStartup') {
    if ($Python -eq '' -or $SourceRoot -eq '') {
        Write-Output 'FAIL stage=preflight exit=2 error=Python and SourceRoot are required'
        exit 2
    }
    $profile = $env:USERPROFILE
    $install = Join-Path $profile 'claude1-assignment-candidate'
    $venvPython = Join-Path $install 'claude1-assignment-venv\Scripts\python.exe'
    $state = Join-Path $install 'state'
    $config = Join-Path $profile 'claude1-worker-config'
    foreach ($path in @($install, $venvPython, $config)) {
        Test-Reparse $path
    }
    if (-not (Test-Path -LiteralPath $venvPython)) {
        Write-Output 'FAIL stage=register exit=2 error=venv python is missing'
        exit 2
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User.Value
    $account = "$env:USERDOMAIN\$env:USERNAME"
    $xmlPath = Join-Path $install 'claude1-assignment-worker.xml'
    $env:PYTHONPATH = $SourceRoot
    & $Python -m free_claude_code.assignments.startup_task emit-xml --user $account --user-sid $sid --python $venvPython --state $state --config $config --xml-out $xmlPath
    if ($LASTEXITCODE -ne 0) {
        exit 2
    }
    & schtasks.exe /Create /TN $TaskName /XML $xmlPath /F
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
    exit $code
}

if ($Root -eq '') {
    Write-Output 'FAIL stage=preflight exit=2 error=Root is required'
    exit 2
}
$resolved = [System.IO.Path]::GetFullPath($Root)
Test-Reparse $resolved

if ($Mode -eq 'ShowContract') {
    $code = Invoke-Candidate 'show-contract'
    if ($code -ne 0) {
        Write-Output "FAIL stage=show-contract exit=$code error=contract was not loaded"
    }
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

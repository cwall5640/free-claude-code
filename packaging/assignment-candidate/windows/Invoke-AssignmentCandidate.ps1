# Candidate only. ShowContract is the only mode that exits 0.
# Install and Activate stay disabled. This file is not a live installer.
param(
    [ValidateSet('ShowContract', 'Install', 'Activate')]
    [string]$Mode = 'ShowContract'
)

$ErrorActionPreference = 'Stop'

if ($Mode -ne 'ShowContract') {
    Write-Output "FAIL stage=activation exit=2 error=startup installer is disabled"
    exit 2
}

Write-Output "OK stage=show-contract exit=0 activation=disabled"
exit 0

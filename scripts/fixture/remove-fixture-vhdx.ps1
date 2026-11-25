[CmdletBinding()]
param(
    [string]$Path = ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\target\ntfs-fixture.vhdx")))
)

$ErrorActionPreference = "Stop"
$Path = [System.IO.Path]::GetFullPath($Path)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "This script must be run as Administrator."
}

$dpScript = [System.IO.Path]::GetTempFileName()
try {
    $commands = @"
select vdisk file="$Path"
detach vdisk
"@
    Set-Content -Path $dpScript -Value $commands
    Write-Host "Running diskpart to detach VHDX ($Path)..."
    & diskpart /s $dpScript | Out-Null
} finally {
    if (Test-Path $dpScript) {
        Remove-Item -Force $dpScript
    }
}

if (Test-Path $Path) {
    Write-Host "Removing VHDX file $Path..."
    Remove-Item -Force $Path
}

Write-Host "VHDX fixture successfully detached and removed."

[CmdletBinding()]
param(
    [string]$Path = ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\target\ntfs-fixture.vhdx"))),
    [int]$SizeMB = 2048,
    [string]$Letter = "R"
)

$ErrorActionPreference = "Stop"
$Path = [System.IO.Path]::GetFullPath($Path)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "This script must be run as Administrator."
}

$parentDir = Split-Path -Parent $Path
if ($parentDir -and -not (Test-Path $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
}

if (Test-Path $Path) {
    Write-Host "Existing VHDX found at $Path; detaching and cleaning up..."
    $cleanupScript = [System.IO.Path]::GetTempFileName()
    try {
        Set-Content -Path $cleanupScript -Value "select vdisk file=`"$Path`"`ndetach vdisk"
        & diskpart /s $cleanupScript | Out-Null
    } finally {
        if (Test-Path $cleanupScript) {
            Remove-Item -Force $cleanupScript
        }
    }
    Remove-Item -Force $Path -ErrorAction SilentlyContinue
}

$dpScript = [System.IO.Path]::GetTempFileName()
try {
    $commands = @"
create vdisk file="$Path" maximum=$SizeMB type=expandable
select vdisk file="$Path"
attach vdisk
create partition primary
format fs=ntfs quick label=DSKFIX
assign letter=$Letter
"@
    Set-Content -Path $dpScript -Value $commands
    Write-Host "Running diskpart to create, format, and mount VHDX ($Letter`:)..."
    & diskpart /s $dpScript
    if ($LASTEXITCODE -ne 0) {
        throw "diskpart failed with exit code $LASTEXITCODE"
    }
} finally {
    if (Test-Path $dpScript) {
        Remove-Item -Force $dpScript
    }
}

$driveRoot = "${Letter}:\"
Write-Host "Populating fixture on $driveRoot via dsk-fixture..."
$env:Path += ";$env:USERPROFILE\.cargo\bin"
& cargo run --release -p dsk-fixture -- $driveRoot
if ($LASTEXITCODE -ne 0) {
    throw "cargo run -p dsk-fixture failed with exit code $LASTEXITCODE"
}

Write-Host "Fixture VHDX successfully created, mounted at $driveRoot, and populated."

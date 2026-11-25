<#
.SYNOPSIS
Packages all four Windows x86_64 release binaries, documentation, and dual licenses into a
portable archive with SHA-256 verification sums.
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$SkipBuild,
    [string]$OutDir = "target\dist"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot

try {
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $cargoToml = Get-Content -Raw (Join-Path $RepoRoot "Cargo.toml")
        if ($cargoToml -match '(?m)^version\s*=\s*"([^"]+)"') {
            $Version = $Matches[1]
        } else {
            throw "Could not determine workspace version from Cargo.toml; pass -Version explicitly."
        }
    }
    $Version = $Version.TrimStart('v', 'V')

    if (-not $SkipBuild) {
        $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
        if ((Test-Path $cargoBin) -and -not ($env:Path -split ';' | Where-Object { $_ -eq $cargoBin })) {
            $env:Path += ";$cargoBin"
        }
        Write-Host "Building release workspace..."
        cargo build --release --workspace
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release --workspace failed with exit code $LASTEXITCODE"
        }
    }

    $releaseDir = Join-Path $RepoRoot "target\release"
    $binaries = @(
        "disksaver.exe",
        "disksaver-gui.exe",
        "dsk-helper.exe",
        "disksaver-tray.exe"
    )
    $docs = @(
        "README.md",
        "LICENSE-MIT",
        "LICENSE-APACHE"
    )

    $resolvedOut = if ([System.IO.Path]::IsPathRooted($OutDir)) {
        $OutDir
    } else {
        Join-Path $RepoRoot $OutDir
    }

    $bundleName = "disksaver-v$Version-windows-x86_64"
    $stageDir = Join-Path $resolvedOut $bundleName
    $zipPath = Join-Path $resolvedOut "$bundleName.zip"
    $sumsPath = Join-Path $resolvedOut "SHA256SUMS.txt"

    if (Test-Path $stageDir) {
        Remove-Item -Recurse -Force $stageDir
    }
    if (Test-Path $zipPath) {
        Remove-Item -Force $zipPath
    }
    if (Test-Path $sumsPath) {
        Remove-Item -Force $sumsPath
    }

    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

    foreach ($bin in $binaries) {
        $src = Join-Path $releaseDir $bin
        if (-not (Test-Path $src)) {
            throw "Missing release binary '$src'. Run without -SkipBuild first."
        }
        Copy-Item -Path $src -Destination (Join-Path $stageDir $bin) -Force
    }

    foreach ($doc in $docs) {
        $src = Join-Path $RepoRoot $doc
        if (-not (Test-Path $src)) {
            throw "Missing required documentation/license file '$src'."
        }
        Copy-Item -Path $src -Destination (Join-Path $stageDir $doc) -Force
    }

    Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal -Force
    Remove-Item -Recurse -Force $stageDir

    $hash = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
    $zipFileName = Split-Path -Leaf $zipPath
    $sumLine = "$hash  $zipFileName"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($sumsPath, "$sumLine`n", $utf8NoBom)

    Write-Host "Created release archive : $zipPath"
    Write-Host "Created SHA-256 sums    : $sumsPath"
    Write-Host "SHA256SUMS entry        : $sumLine"
}
finally {
    Pop-Location
}

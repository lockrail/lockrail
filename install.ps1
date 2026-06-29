# Lockrail installer for Windows
# Usage: irm https://raw.githubusercontent.com/lockrail/lockrail/main/install.ps1 | iex
#
# Or, to choose the install directory:
#   $env:LOCKRAIL_INSTALL = "C:\Tools\lockrail"; irm .../install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo   = "lockrail/lockrail"
$Binary = "lockrail.exe"
$Target = "x86_64-pc-windows-msvc"

function Write-Step { Write-Host "  $([char]0x2022) $args" -ForegroundColor Cyan }
function Write-Ok   { Write-Host "  $([char]0x2713) $args" -ForegroundColor Green }
function Write-Fail { Write-Host "  $([char]0x2717) $args" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  Lockrail installer" -ForegroundColor Bold
Write-Host ""

# ── resolve install directory ───────────────────────────────────────────────────
$InstallDir = if ($env:LOCKRAIL_INSTALL) {
    $env:LOCKRAIL_INSTALL
} else {
    "$env:USERPROFILE\.local\bin"
}
Write-Step "Install directory: $InstallDir"

# ── fetch latest release tag ────────────────────────────────────────────────────
Write-Step "Fetching latest release tag..."
try {
    $Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "lockrail-installer" }
    $Tag = $Release.tag_name
} catch {
    Write-Fail "Could not fetch latest release. Check your internet connection or visit https://github.com/$Repo/releases"
}
Write-Step "Latest release: $Tag"

# ── download binary ─────────────────────────────────────────────────────────────
$BinaryName  = "lockrail-$Target.exe"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/$BinaryName"
$Sha256Url   = "https://github.com/$Repo/releases/download/$Tag/$BinaryName.sha256"

$TmpDir = Join-Path $env:TEMP "lockrail-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir | Out-Null
$TmpBin = Join-Path $TmpDir $Binary
$TmpSha = Join-Path $TmpDir "lockrail.sha256"

Write-Step "Downloading $DownloadUrl..."
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpBin -UseBasicParsing
} catch {
    Remove-Item $TmpDir -Recurse -Force
    Write-Fail "Download failed: $_"
}

# ── verify checksum ─────────────────────────────────────────────────────────────
try {
    Invoke-WebRequest -Uri $Sha256Url -OutFile $TmpSha -UseBasicParsing
    $Expected = (Get-Content $TmpSha -Raw).Split()[0].ToLower()
    $Actual   = (Get-FileHash $TmpBin -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        Remove-Item $TmpDir -Recurse -Force
        Write-Fail "Checksum mismatch! Expected $Expected, got $Actual"
    }
    Write-Ok "Checksum verified"
} catch {
    Write-Step "Could not verify checksum (non-fatal), continuing..."
}

# ── install ─────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $TmpBin (Join-Path $InstallDir $Binary) -Force
Remove-Item $TmpDir -Recurse -Force
Write-Ok "Installed to $InstallDir\$Binary"

# ── add to PATH if needed ────────────────────────────────────────────────────────
$UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable(
        "PATH",
        "$InstallDir;$UserPath",
        "User"
    )
    $env:PATH = "$InstallDir;$env:PATH"
    Write-Ok "Added $InstallDir to your user PATH (restart your shell to take effect)"
} else {
    Write-Step "$InstallDir is already in PATH"
}

# ── verify ───────────────────────────────────────────────────────────────────────
try {
    $Version = & "$InstallDir\$Binary" --version 2>&1
    Write-Ok $Version
} catch {
    Write-Step "Run 'lockrail --version' to verify the install"
}

Write-Host ""
Write-Host "  Quick start:" -ForegroundColor Bold
Write-Host "    lockrail init"
Write-Host "    lockrail protect --tool all"
Write-Host "    lockrail demo"
Write-Host "    lockrail ui        # dashboard at http://127.0.0.1:8790"
Write-Host ""
Write-Ok "Done. Run 'lockrail --help' to get started."
Write-Host ""

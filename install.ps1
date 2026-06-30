# Lockrail installer for Windows
# Usage: irm https://raw.githubusercontent.com/lockrail/lockrail/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "lockrail/lockrail"
$Binary = "lockrail.exe"
$Target = "x86_64-pc-windows-msvc"

function Write-Banner {
    Write-Host ""
    Write-Host "lockrail//installer" -ForegroundColor Cyan -NoNewline
    Write-Host " secret firewall bootstrap" -ForegroundColor DarkGray
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
}
function Write-Step($N, $Text) { Write-Host ("[{0}] {1}" -f $N, $Text) -ForegroundColor Cyan }
function Write-Ok($Text) { Write-Host ("[ok] {0}" -f $Text) -ForegroundColor Green }
function Write-Fail($Text) { Write-Host ("[!!] {0}" -f $Text) -ForegroundColor Red; exit 1 }
function Write-ProgressLine($Text) { Write-Host ("     {0,-20} [##########] done" -f $Text) -ForegroundColor DarkGray }

Write-Banner

Write-Step "01" "scanning host kernel"
if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Fail "32-bit Windows is not supported"
}
Write-Ok "host=windows/x86_64"

Write-Step "02" "selecting release artifact"
Write-Ok "target=$Target"

Write-Step "03" "querying github releases"
try {
    $Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "lockrail-installer" }
    $Tag = $Release.tag_name
} catch {
    Write-Fail "could not resolve latest release; visit https://github.com/$Repo/releases"
}
Write-Ok "release=$Tag"

Write-Step "04" "choosing install path"
$InstallDir = if ($env:LOCKRAIL_INSTALL) { $env:LOCKRAIL_INSTALL } else { "$env:USERPROFILE\.local\bin" }
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Write-Ok "path=$InstallDir"

$Artifact = "lockrail-$Target.exe"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/$Artifact"
$Sha256Url = "$DownloadUrl.sha256"
$TmpDir = Join-Path $env:TEMP "lockrail-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir | Out-Null
$TmpBin = Join-Path $TmpDir $Binary
$TmpSha = Join-Path $TmpDir "lockrail.sha256"

try {
    Write-Step "05" "pulling binary payload"
    Write-ProgressLine "download"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpBin -UseBasicParsing | Out-Null

    Write-Step "06" "verifying payload hash"
    Invoke-WebRequest -Uri $Sha256Url -OutFile $TmpSha -UseBasicParsing | Out-Null
    $Expected = (Get-Content $TmpSha -Raw).Split()[0].ToLower()
    $Actual = (Get-FileHash $TmpBin -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        Write-Fail "checksum mismatch; aborting"
    }
    Write-Ok "sha256=$Actual"

    Write-Step "07" "arming executable"
    Copy-Item $TmpBin (Join-Path $InstallDir $Binary) -Force
    Write-Ok "installed=$InstallDir\$Binary"
} finally {
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

$UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$UserPath", "User")
    $env:PATH = "$InstallDir;$env:PATH"
    Write-Ok "added $InstallDir to user PATH"
}

try {
    $Version = & "$InstallDir\$Binary" --version 2>&1
    Write-Ok $Version
} catch {
    Write-Host "Run 'lockrail --version' to verify the install" -ForegroundColor Yellow
}

Write-Step "08" "auto-configuring local firewall"
& "$InstallDir\$Binary" setup
if ($LASTEXITCODE -ne 0) {
    Write-Fail "setup failed; run $InstallDir\$Binary setup for details"
}

Write-Host ""
Write-Host "next commands" -ForegroundColor White
Write-Host "  lockrail demo"
Write-Host "  lockrail ui"
Write-Host "  claude   # or codex / cursor / agy if installed"
Write-Host ""
Write-Ok "bootstrap complete"

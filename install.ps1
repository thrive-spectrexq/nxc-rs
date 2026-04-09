# NetExec-RS (nxc) Installer for Windows
# This script downloads the latest pre-compiled binary from GitHub.

$ErrorActionPreference = "Stop"

Write-Host "◈ NetExec-RS Installer ◈" -ForegroundColor Cyan

$Repo = "thrive-spectrexq/nxc-rs"
$AssetName = "nxc-windows-amd64.exe"
$BinaryName = "nxc.exe"

# 1. Check Architecture
if ([IntPtr]::Size -ne 8) {
    Write-Host "[!] Error: Only 64-bit architecture is currently supported via this script." -ForegroundColor Red
    exit 1
}

# 2. Download
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/$AssetName"
Write-Host "[*] Downloading latest release ($AssetName)..." -ForegroundColor Cyan

$InstallDir = Join-Path $env:USERPROFILE ".nxc"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir
}

$BinaryPath = Join-Path $InstallDir $BinaryName
Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath

# 3. Path Management
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", $UserPath + ";$InstallDir", "User")
    $env:Path += ";$InstallDir"
    Write-Host "[*] Added $InstallDir to User PATH." -ForegroundColor Yellow
}

Write-Host "[+] NetExec-RS (nxc) installed successfully!" -ForegroundColor Green
Write-Host "[+] Usage: nxc --help" -ForegroundColor Green
Write-Host "[!] Note: You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Yellow

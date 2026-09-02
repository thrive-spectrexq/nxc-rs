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

# 2.1 Verify Checksum if available
$ChecksumUrl = "$DownloadUrl.sha256"
try {
    $ExpectedHashContent = (Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing -ErrorAction SilentlyContinue).Content
    if ($ExpectedHashContent) {
        Write-Host "[*] Verifying SHA256 checksum..." -ForegroundColor Cyan
        $ExpectedHash = ($ExpectedHashContent.Trim() -split '\s+')[0].ToLower()
        $ActualHash = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash.ToLower()
        if ($ExpectedHash -and ($ExpectedHash -ne $ActualHash)) {
            Write-Host "[!] Error: Checksum verification failed!" -ForegroundColor Red
            Write-Host "[!] Expected: $ExpectedHash, Got: $ActualHash" -ForegroundColor Red
            Remove-Item $BinaryPath -Force
            exit 1
        }
        Write-Host "[+] Checksum verified successfully." -ForegroundColor Green
    }
} catch {
    Write-Host "[*] Release checksum not reachable; continuing with installation." -ForegroundColor DarkGray
}

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

# NetExec-RS (nxc) Installer for Windows
# This script installs the Rust toolchain if missing and builds nxc from source.

$ErrorActionPreference = "Stop"

Write-Host "◈ NetExec-RS Installer ◈" -ForegroundColor Cyan

# 1. Check for Rust
if (Get-Command "cargo" -ErrorAction SilentlyContinue) {
    Write-Host "[+] Rust is already installed." -ForegroundColor Green
} else {
    Write-Host "[*] Rust not found. Installing via rustup..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile "$env:TEMP\rustup-init.exe"
    Start-Process -FilePath "$env:TEMP\rustup-init.exe" -ArgumentList "-y" -Wait
    $env:Path += ";$env:USERPROFILE\.cargo\bin"
    Write-Host "[+] Rust installed." -ForegroundColor Green
}

# 2. Build
Write-Host "[*] Building NetExec-RS (nxc) in release mode..." -ForegroundColor Cyan
cargo build --release --package nxc

# 3. Path Management
$BinaryName = "nxc.exe"
$BinaryPath = "target\release\$BinaryName"

if (Test-Path $BinaryPath) {
    $InstallDir = "$env:USERPROFILE\.nxc"
    if (!(Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir
    }
    Copy-Item $BinaryPath -Destination "$InstallDir\$BinaryName" -Force
    
    # Add to Path if not already there
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", $UserPath + ";$InstallDir", "User")
        $env:Path += ";$InstallDir"
        Write-Host "[*] Added $InstallDir to User PATH." -ForegroundColor Yellow
    }
    
    Write-Host "[+] NetExec-RS (nxc) installed successfully!" -ForegroundColor Green
    Write-Host "[+] Usage: nxc --help" -ForegroundColor Green
    Write-Host "[!] Note: You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
} else {
    Write-Host "[!] Build failed. Binary not found at $BinaryPath" -ForegroundColor Red
    exit 1
}

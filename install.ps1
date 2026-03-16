# NetSage Windows Installer
# Repository: https://github.com/thrive-spectrexq/netsage

$ErrorActionPreference = "Stop"

Write-Host "🚀 Installing NetSage for Windows..." -ForegroundColor Cyan

# 1. Dependency Checks
Write-Host "🔍 Checking dependencies..."
if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Error: Rust (cargo) is not installed. Please install it from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# 2. Setup Directory
$NETSAGE_DIR = "$HOME\.netsage"
if (Test-Path $NETSAGE_DIR) {
    Write-Host "📂 Updating existing NetSage installation..."
    Set-Location $NETSAGE_DIR
    git pull
} else {
    Write-Host "📥 Cloning NetSage repository..."
    git clone https://github.com/thrive-spectrexq/netsage.git $NETSAGE_DIR
    Set-Location $NETSAGE_DIR
}

# 3. Check for Npcap
if (!(Test-Path "C:\Windows\System32\wpcap.dll")) {
    Write-Host "⚠️ Warning: Npcap not found. Network capture may require Npcap installed in 'WinPcap API-compatible mode'." -ForegroundColor Yellow
}

# 5. Build and Install Rust Binary
Write-Host "Cr Building NetSage (this may take a few minutes)..." -ForegroundColor Cyan
cargo install --path crates/netsage

Write-Host ""
Write-Host "✅ NetSage installed successfully!" -ForegroundColor Green
Write-Host "--------------------------------------------------"
Write-Host "Next Steps:"
Write-Host "1. Set your API key:"
Write-Host '   $env:GEMINI_API_KEY="your_key_here"'
Write-Host "2. Create a NETWORK.md file for network context."
Write-Host "3. Run 'netsage' anywhere in your terminal."
Write-Host "--------------------------------------------------"

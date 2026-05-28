# RAMDetect PTM Repository Server Startup
# Auto-detects the PTM server LAN IPv4 address and prints client workstation setup commands.
# NOTE: Keep this file private because it contains repository API tokens.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# 1. Project paths
# ============================================================
$ServerRoot = "C:\Users\annsi\Downloads\GITHUB\RAMDetect_PTM_Server"
$RepositoryRoot = "C:\Users\annsi\Downloads\GITHUB\RAMDetect_PTM_ReportRepository"

if (-not (Test-Path $ServerRoot)) {
    Write-Host "[ERROR] PTM server folder not found: $ServerRoot" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $RepositoryRoot)) {
    New-Item -ItemType Directory -Path $RepositoryRoot -Force | Out-Null
}

Set-Location $ServerRoot

# ============================================================
# 2. Activate PTM server virtual environment
# ============================================================
$Activate = Join-Path $ServerRoot ".venv\Scripts\Activate.ps1"

if (Test-Path $Activate) {
    . $Activate
} else {
    Write-Host "[WARN] PTM server venv activation script not found:" -ForegroundColor Yellow
    Write-Host "       $Activate" -ForegroundColor Yellow
    Write-Host "       Continuing with current Python environment..." -ForegroundColor Yellow
}

# ============================================================
# 3. PTM repository configuration
# ============================================================
$env:RAMDETECT_PTM_REPOSITORY_ROOT = $RepositoryRoot
$env:RAMDETECT_PTM_REPOSITORY_DB = Join-Path $RepositoryRoot "repository.db"

# ============================================================
# 4. Repository tokens
#    Keep this file private. Do not commit real tokens to GitHub.
# ============================================================
$env:RAMDETECT_REPOSITORY_ADMIN_TOKEN = "0BB71222D97491E9A36ED3270876238617907FA5747D00824CFA21583F289369"
$env:RAMDETECT_REPOSITORY_CLIENT_TOKEN = "47E0E97E0C43756EE7636F55A0010A8A51339430DBA403C14849F02DC3767DDE"

# ============================================================
# 5. Auto-detect suitable LAN IPv4 address
#    Preference order:
#    1. Wi-Fi / Ethernet with default gateway
#    2. Exclude Radmin VPN / VMware / VirtualBox / Hyper-V / Bluetooth / loopback
#    3. Exclude known virtual/VPN ranges used in this project
# ============================================================
function Get-RAMDetectServerIPv4 {
    $ignoredAdapterPattern = "Radmin|VMware|VirtualBox|Hyper-V|Bluetooth|Loopback|Teredo|Pseudo"
    $ignoredIpPatterns = @(
        "127.*",          # loopback
        "169.254.*",      # APIPA
        "26.*",           # Radmin VPN in this environment
        "192.168.84.*",   # VMware VMnet1 in this environment
        "192.168.216.*"   # VMware VMnet8 in this environment
    )

    $configs = Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4Address -and
            $_.NetAdapter.Status -eq "Up" -and
            $_.NetAdapter.InterfaceDescription -notmatch $ignoredAdapterPattern -and
            $_.InterfaceAlias -notmatch $ignoredAdapterPattern
        }

    $valid = foreach ($cfg in $configs) {
        foreach ($addr in $cfg.IPv4Address) {
            $ip = $addr.IPAddress
            $blocked = $false

            foreach ($pat in $ignoredIpPatterns) {
                if ($ip -like $pat) {
                    $blocked = $true
                    break
                }
            }

            if (-not $blocked) {
                [PSCustomObject]@{
                    IP = $ip
                    Alias = $cfg.InterfaceAlias
                    Description = $cfg.NetAdapter.InterfaceDescription
                    HasGateway = [bool]$cfg.IPv4DefaultGateway
                }
            }
        }
    }

    # Prefer normal Wi-Fi/Ethernet adapter with a default gateway.
    $preferred = $valid |
        Sort-Object `
            @{ Expression = { if ($_.HasGateway) { 0 } else { 1 } } }, `
            @{ Expression = { if ($_.Alias -match "Wi-Fi|Ethernet") { 0 } else { 1 } } }, `
            Alias |
        Select-Object -First 1

    if ($preferred) {
        return $preferred.IP
    }

    # Last fallback: any non-loopback IPv4.
    $fallback = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -notlike "26.*"
        } |
        Select-Object -ExpandProperty IPAddress -First 1

    return $fallback
}

$ServerIp = Get-RAMDetectServerIPv4

if (-not $ServerIp) {
    $ServerIp = "<PTM_SERVER_IP>"
    Write-Host "[WARN] Could not auto-detect LAN IPv4 address. Replace <PTM_SERVER_IP> manually." -ForegroundColor Yellow
}

# PowerShell variable interpolation note:
# Use ${ServerIp} when followed by a colon, otherwise strings like http://$ServerIp:8765 can render incorrectly.
$PtmApiUrl = "http://${ServerIp}:8765"
$PostgresUrl = "postgresql+psycopg2://ramdetect_app:changeme@${ServerIp}:5432/ramdetect_db"

# ============================================================
# 6. Console display for client workstation setup
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " RAMDetect PTM Server Startup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Detected PTM Server IP : $ServerIp" -ForegroundColor Green
Write-Host "PTM API URL            : $PtmApiUrl" -ForegroundColor Green
Write-Host "PostgreSQL URL         : $PostgresUrl" -ForegroundColor Green
Write-Host ""
Write-Host "Configure the installed ANALYST workstation:" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host 'cd "C:\RAMDetect Analyst"'
Write-Host "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
Write-Host ".\Configure_RAMDetect_Analyst_Server.ps1 ``"
Write-Host "  -ServerIP `"$ServerIp`" ``"
Write-Host "  -ClientToken `"$($env:RAMDETECT_REPOSITORY_CLIENT_TOKEN)`""
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Configure the installed ADMIN workstation:" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host 'cd "C:\RAMDetect Admin"'
Write-Host "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
Write-Host ".\Configure_RAMDetect_Admin_Server.ps1 ``"
Write-Host "  -ServerIP `"$ServerIp`" ``"
Write-Host "  -ClientToken `"$($env:RAMDETECT_REPOSITORY_CLIENT_TOKEN)`" ``"
Write-Host '  -AdminToken "<ADMIN_TOKEN_FROM_PRIVATE_SERVER_CONFIG>"'
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Notes:" -ForegroundColor Yellow
Write-Host "- Use the ANALYST script for analyst/client workstations. It intentionally leaves the admin token empty."
Write-Host "- Use the ADMIN script only on the admin workstation and paste the private admin token when prompted in the command above."
Write-Host "- If RAMDetect was installed into a different folder, cd to that installed folder first."
Write-Host ""
Write-Host "Client verification commands:" -ForegroundColor Yellow
Write-Host "python -c `"from sqlalchemy import create_engine; import os; e=create_engine(os.getenv('RAMDETECT_DB_URL')); print(e.connect().exec_driver_sql('SELECT 1').scalar())`""
Write-Host "Invoke-RestMethod $PtmApiUrl/health"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] If clients cannot connect, ensure firewall allows TCP 8765 and PostgreSQL allows TCP 5432." -ForegroundColor Yellow
Write-Host "[INFO] PostgreSQL pg_hba.conf must allow the client network, e.g. 172.20.10.0/24." -ForegroundColor Yellow
Write-Host "[INFO] Leave this PowerShell window open while clients are using the PTM Repository Server." -ForegroundColor Yellow
Write-Host ""

# ============================================================
# 7. Start FastAPI / Uvicorn server
# ============================================================
uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765


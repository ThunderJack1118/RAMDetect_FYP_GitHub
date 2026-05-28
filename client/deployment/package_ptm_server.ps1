# Create a sanitized RAMDetect_PTM_Server.zip for deployment.
# Run from the parent folder that contains RAMDetect_PTM_Server.

param(
    [string] $ServerFolder = ".\RAMDetect_PTM_Server",
    [string] $OutputZip = ".\release\RAMDetect_PTM_Server.zip"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $ServerFolder)) {
    throw "PTM server folder not found: $ServerFolder"
}

$OutputDir = Split-Path $OutputZip -Parent
if ($OutputDir) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

$Temp = Join-Path $env:TEMP ("RAMDetect_PTM_Server_Package_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null

$Dest = Join-Path $Temp "RAMDetect_PTM_Server"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

$include = @(
    "ptm_report_repository_server.py",
    "requirements_repository_server.txt",
    "README_PTM_STRICT_DEPLOYMENT.md",
    "ptm_repository_env_example.ps1"
)

foreach ($f in $include) {
    $src = Join-Path $ServerFolder $f
    if (Test-Path $src) {
        Copy-Item $src -Destination $Dest -Force
    } else {
        Write-Host "[WARN] Missing optional file: $src" -ForegroundColor Yellow
    }
}

# Do not copy real-token startup scripts by default.
# Instead create a safe startup template.
@'
# RAMDetect PTM Repository Server Startup Template
# Replace token placeholders before running. Do not commit real-token copies.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServerRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = "C:\RAMDetect_PTM_ReportRepository"

New-Item -ItemType Directory -Force -Path $RepositoryRoot | Out-Null
Set-Location $ServerRoot

if (-not (Test-Path ".\.venv")) {
    py -3.10 -m venv .venv
}

. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements_repository_server.txt

$env:RAMDETECT_PTM_REPOSITORY_ROOT = $RepositoryRoot
$env:RAMDETECT_PTM_REPOSITORY_DB = Join-Path $RepositoryRoot "repository.db"
$env:RAMDETECT_REPOSITORY_ADMIN_TOKEN = "REPLACE_WITH_LONG_RANDOM_ADMIN_TOKEN"
$env:RAMDETECT_REPOSITORY_CLIENT_TOKEN = "REPLACE_WITH_LONG_RANDOM_CLIENT_UPLOAD_TOKEN"

uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765
'@ | Set-Content -Path (Join-Path $Dest "start_ptm_server.template.ps1") -Encoding UTF8

if (Test-Path $OutputZip) { Remove-Item $OutputZip -Force }
Compress-Archive -Path $Dest -DestinationPath $OutputZip -Force
Remove-Item $Temp -Recurse -Force

Write-Host "Created sanitized PTM server package: $OutputZip" -ForegroundColor Green

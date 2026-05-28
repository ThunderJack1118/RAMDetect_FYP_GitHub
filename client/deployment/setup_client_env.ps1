# Configure RAMDetect Analyst Client environment variables.
# Analyst clients must not receive the admin token.

param(
    [Parameter(Mandatory=$true)] [string] $PtmServerIp,
    [Parameter(Mandatory=$true)] [string] $ClientToken,
    [string] $DbUser = "ramdetect_app",
    [string] $DbPassword = "changeme",
    [string] $DbName = "ramdetect_db",
    [int] $DbPort = 5432,
    [int] $ApiPort = 8765
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DbUrl = "postgresql+psycopg2://$DbUser`:$DbPassword@$PtmServerIp`:$DbPort/$DbName"
$ApiUrl = "http://$PtmServerIp`:$ApiPort"

setx RAMDETECT_DB_URL "$DbUrl" | Out-Null
setx RAMDETECT_REPOSITORY_API_URL "$ApiUrl" | Out-Null
setx RAMDETECT_REPOSITORY_API_TOKEN "$ClientToken" | Out-Null
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN "" | Out-Null

Write-Host "RAMDetect Analyst Client environment configured." -ForegroundColor Green
Write-Host "DB URL : $DbUrl"
Write-Host "API URL: $ApiUrl"
Write-Host "ADMIN_TOKEN is intentionally empty for analyst clients." -ForegroundColor Yellow
Write-Host "Close and reopen PowerShell, then launch RAMDetect." -ForegroundColor Cyan

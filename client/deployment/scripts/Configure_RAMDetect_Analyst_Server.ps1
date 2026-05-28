param(
    [Parameter(Mandatory=$true)][string]$ServerIP,
    [Parameter(Mandatory=$true)][string]$ClientToken,
    [string]$DbUser = "ramdetect_app",
    [string]$DbPassword = "changeme",
    [string]$DbName = "ramdetect_db",
    [int]$DbPort = 5432,
    [int]$ApiPort = 8765
)

setx RAMDETECT_RUNTIME_MODE "auto"
setx RAMDETECT_DB_URL "postgresql+psycopg2://$DbUser`:$DbPassword@$ServerIP`:$DbPort/$DbName"
setx RAMDETECT_REPOSITORY_API_URL "http://$ServerIP`:$ApiPort"
setx RAMDETECT_REPOSITORY_API_TOKEN "$ClientToken"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN ""

Write-Host ""
Write-Host "[RAMDetect] Analyst server configuration saved." -ForegroundColor Green

$RuntimeEnvFile = Join-Path $PSScriptRoot "RAMDetect_RUNTIME.env"
@"
RAMDETECT_RUNTIME_MODE=auto
RAMDETECT_DB_URL=postgresql+psycopg2://$DbUser`:$DbPassword@$ServerIP`:$DbPort/$DbName
RAMDETECT_REPOSITORY_API_URL=http://$ServerIP`:$ApiPort
RAMDETECT_REPOSITORY_API_TOKEN=$ClientToken
RAMDETECT_REPOSITORY_ADMIN_API_TOKEN=
"@ | Set-Content $RuntimeEnvFile -Encoding UTF8

Write-Host "[RAMDetect] Local runtime env written to: $RuntimeEnvFile" -ForegroundColor Green

Write-Host "Close and reopen RAMDetect for changes to take effect."
Write-Host "Admin token is intentionally empty on Analyst workstation."

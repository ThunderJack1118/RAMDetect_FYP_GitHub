# Prepare RAMDetect source tree before first private GitHub commit.
# Run from the RAMDetect project root after reviewing the changes.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\main.py")) {
    throw "main.py not found. Run from RAMDetect project root."
}

Write-Host "[1/5] Creating writable runtime folders..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path ".\dumps", ".\reports", ".\logs", ".\temp" | Out-Null

Write-Host "[2/5] Removing local virtual environment folders from source tree..." -ForegroundColor Cyan
foreach ($d in @(".\venv", ".\.venv", ".\venvvenv")) {
    if (Test-Path $d) {
        Write-Host "Removing $d" -ForegroundColor Yellow
        Remove-Item $d -Recurse -Force
    }
}

Write-Host "[3/5] Patching config.yaml portable acquisition output_dir..." -ForegroundColor Cyan
$configPath = ".\config.yaml"
if (Test-Path $configPath) {
    $text = Get-Content $configPath -Raw
    $text = $text -replace 'output_dir:\s*C:/Users/annsi/Downloads/GITHUB/RAMDetect/dumps', 'output_dir: dumps'
    Set-Content -Path $configPath -Value $text -Encoding UTF8
}

Write-Host "[4/5] Checking for sensitive/runtime files..." -ForegroundColor Cyan
$patterns = @("*.dmp", "*.raw", "*.mem", "*.vmem", "*.db", "*.sqlite", "*.sqlite3")
foreach ($pat in $patterns) {
    $hits = Get-ChildItem -Path . -Recurse -File -Filter $pat -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\.git\\|venv|\.venv|venvvenv' }
    foreach ($h in $hits) {
        Write-Host "Review before commit: $($h.FullName)" -ForegroundColor Yellow
    }
}

Write-Host "[5/5] Source preparation complete." -ForegroundColor Green
Write-Host "Next: git status; git add .; git commit -m 'Prepare RAMDetect deployment source'" -ForegroundColor Green

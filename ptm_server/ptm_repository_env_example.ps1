# PTM Central RAMDetect Report Repository Server environment example
# Run these on the SERVER machine, not on staff PCs.

$env:RAMDETECT_PTM_REPOSITORY_ROOT = "C:\RAMDetect_PTM_ReportRepository"
$env:RAMDETECT_PTM_REPOSITORY_DB = "C:\RAMDetect_PTM_ReportRepository\repository.db"

# Generate strong random tokens before real deployment.
# Example only — replace these values.
$env:RAMDETECT_REPOSITORY_ADMIN_TOKEN = "REPLACE_WITH_LONG_RANDOM_ADMIN_TOKEN"
$env:RAMDETECT_REPOSITORY_CLIENT_TOKEN = "REPLACE_WITH_LONG_RANDOM_CLIENT_UPLOAD_TOKEN"

# Optional Google Drive / Shared Drive backend.
# Keep service-account JSON ONLY on the server.
$env:RAMDETECT_GOOGLE_SERVICE_ACCOUNT_JSON = "C:\RAMDetectSecrets\ramdetect-drive-service-account.json"
$env:RAMDETECT_GOOGLE_DRIVE_FOLDER_ID = "REPLACE_WITH_SHARED_DRIVE_FOLDER_ID"

# Optional: only if PTM enables Workspace domain-wide delegation.
# $env:RAMDETECT_GOOGLE_DELEGATED_USER = "ptm-admin@uthm.edu.my"

uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765

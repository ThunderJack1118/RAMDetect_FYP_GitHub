# RAMDetect Client Workstation Setup
# Replace <PTM_SERVER_IP> and <CLIENT_UPLOAD_TOKEN> before running.

setx RAMDETECT_DB_URL "postgresql+psycopg2://ramdetect_app:changeme@<PTM_SERVER_IP>:5432/ramdetect_db"
setx RAMDETECT_REPOSITORY_API_URL "http://<PTM_SERVER_IP>:8765"
setx RAMDETECT_REPOSITORY_API_TOKEN "47E0E97E0C43756EE7636F55A0010A8A51339430DBA403C14849F02DC3767DDE"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN ""

Write-Host "Client environment variables configured. Close and reopen PowerShell."

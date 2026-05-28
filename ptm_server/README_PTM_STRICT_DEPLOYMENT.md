# RAMDetect Strict PTM Report Repository Deployment

## Goal

Strict deployment means staff PCs do **not** receive Google Drive credentials and do **not** write directly to a shared Drive folder. Instead:

```text
RAMDetect staff PC
  -> HTTPS upload to PTM Repository API using upload-only token
  -> PTM Repository API stores metadata in SQLite
  -> PTM Repository API stores files locally and optionally uploads to Google Drive/Shared Drive using service-account credentials
  -> Admin Activity Monitor lists/downloads using admin-only token
```

This keeps Google credentials and full download authority on the central PTM server only.

## Server setup

```powershell
cd C:\RAMDetect_PTM_Server
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements_repository_server.txt
```

Configure server environment variables in `ptm_repository_env_example.ps1`, then run:

```powershell
uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765
```

Health check:

```powershell
Invoke-RestMethod http://SERVER-IP:8765/health
```


## Quick Start PTM Server (Recommended)

The repository includes a convenience startup script:

```text
start_ptm_server.ps1
```

The script is intended to automate PTM Repository API startup tasks such as:

- activating the virtual environment
- loading environment variables
- starting the FastAPI/uvicorn PTM server
- preparing repository folders

### Run the PTM server script

Open PowerShell:

```powershell
cd C:\RAMDetect_PTM_Server
```

Temporarily allow PowerShell script execution for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Run the startup script:

```powershell
.\start_ptm_server.ps1
```

If the script is configured correctly, the PTM Repository API should start automatically.

### If PowerShell blocks script execution

You may see:

```text
running scripts is disabled on this system
```

Run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then execute the script again.

### Manual startup alternative

If preferred, the PTM Repository API can still be started manually:

```powershell
uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765
```

## Client setup on each RAMDetect workstation

Set upload-only client token:

```powershell
setx RAMDETECT_REPOSITORY_API_URL "http://SERVER-IP:8765"
setx RAMDETECT_REPOSITORY_API_TOKEN "REPLACE_WITH_LONG_RANDOM_CLIENT_UPLOAD_TOKEN"
```

Restart RAMDetect.

## Admin workstation setup

Set admin token:

```powershell
setx RAMDETECT_REPOSITORY_API_URL "http://SERVER-IP:8765"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN "REPLACE_WITH_LONG_RANDOM_ADMIN_TOKEN"
```

Restart RAMDetect. Admin can list/download reports from Activity Monitor.

## Google Drive configuration

The Drive service-account JSON file must be stored only on the central server. Share the destination Google Drive/Shared Drive folder with the service-account email, or configure Workspace domain-wide delegation if PTM requires organization-level control.

Do not place service-account JSON or API tokens inside GitHub.

## Security notes

- Use HTTPS/reverse proxy for real deployment.
- Use different tokens for upload-only clients and admin download access.
- Staff PCs should only have `RAMDETECT_REPOSITORY_API_TOKEN`, not the admin token.
- Admin PC should have `RAMDETECT_REPOSITORY_ADMIN_API_TOKEN`.
- The server verifies SHA-256 during upload.
- The server logs download activity in its central database.
- This repository handles generated reports/exports only. Do not upload raw RAM dumps or live malware samples.

# RAMDetect Admin Client Deployment Guide

## 1. Purpose

RAMDetect Admin Client is the administrator workstation version of RAMDetect. It supports the normal RAMDetect analysis workflow and provides access to Admin Management, central activity monitoring, connected workstation monitoring, and PTM Repository report management.

RAMDetect is a post-incident RAM forensics triage tool for academic FYP deployment. It is not an antivirus, EDR, or real-time malware blocker.

## 2. Installation Path

Default installation path:

```text
C:\RAMDetect Admin
```

Main executable:

```text
C:\RAMDetect Admin\RAMDetect.exe
```

## 3. Admin Access Rule

Admin login requires both:

```text
1. Valid Admin username/password
2. Configured RAMDETECT_REPOSITORY_ADMIN_API_TOKEN
```

If the admin token is missing, Admin login is blocked even when the username and password are correct. This prevents an Analyst workstation from being used to access Admin features.

## 4. Configure Server Connection

When the PTM server IP changes, run the included Admin configuration script:

```powershell
cd "C:\RAMDetect Admin"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\Configure_RAMDetect_Admin_Server.ps1 `
  -ServerIP "192.168.1.36" `
  -ClientToken "<CLIENT_UPLOAD_TOKEN>" `
  -AdminToken "<ADMIN_TOKEN>"
```

After running the script, close and reopen RAMDetect.

The script writes both Windows user environment variables and a local runtime file:

```text
C:\RAMDetect Admin\RAMDetect_RUNTIME.env
```

The local runtime file helps RAMDetect read the latest server settings even when Windows environment variables have not refreshed yet.

## 5. Required PTM Services

Admin Online Mode requires:

```text
PostgreSQL RAMDetect shared database
PTM Repository Server API
Client upload token
Admin repository token
```

The PTM Server API should be reachable from the admin workstation:

```powershell
Invoke-RestMethod http://192.168.1.36:8765/health
```

## 6. Runtime Mode

Recommended mode:

```powershell
setx RAMDETECT_RUNTIME_MODE "auto"
```

Auto mode allows RAMDetect to use Online Mode when the PTM server and PostgreSQL database are reachable.

## 7. Admin Functions

Admin users can access:

```text
Admin Management
Activity Monitor
Central report repository downloads
Connected workstation monitoring
User and workstation management
Normal RAM dump analysis workflow
```

Analyst users can still run the normal workflow but cannot access Admin Management.

## 8. Admin Validation Checklist

After installation:

```text
1. Run Configure_RAMDetect_Admin_Server.ps1 with server IP, client token, and admin token.
2. Close and reopen RAMDetect.
3. Login using an Admin account.
4. Confirm Admin Management is visible.
5. Confirm Activity Monitor loads central activity data.
6. Confirm central repository report list/download works.
7. Confirm Analyst installer still blocks Admin login when the admin token is empty.
```

## 9. Local Storage Rules

Imported or acquired dumps are stored under:

```text
<current RAMDetect folder>\dumps\<session>\
```

Reports are stored under:

```text
<current RAMDetect folder>\reports\
```

Runtime session data is stored under:

```text
<current RAMDetect folder>\ui\data\
<current RAMDetect folder>\ramdetect\ui\data\
```

Do not manually edit activity logs. RAMDetect records activity automatically.

## 10. Volatility-Assisted Functions

The deployed Admin Client includes a bundled Volatility runner for the two documented Volatility-assisted exceptions:

```text
windows.info.Info  - DTB / OS profile / architecture metadata support
windows.handles    - handle enumeration support
```

These functions support artifact extraction and metadata resolution only. They do not override the final ML verdict.

If `windows.handles` fails or times out, RAMDetect continues analysis without handle artifacts.

## 11. Machine Learning Runtime

The packaged Admin Client uses the NumPy Autoencoder runtime file:

```text
models\autoencoder_numpy_runtime.npz
```

This avoids TensorFlow DLL runtime errors in the standalone build while preserving the RF-AE input design. The final verdict remains ML-only.

## 12. Troubleshooting

Check PTM API health:

```powershell
Invoke-RestMethod http://<PTM_SERVER_IP>:8765/health
```

Check database connection:

```powershell
python -c "from sqlalchemy import create_engine; import os; e=create_engine(os.getenv('RAMDETECT_DB_URL')); print(e.connect().exec_driver_sql('SELECT 1').scalar())"
```

Check admin runtime file:

```powershell
Get-Content "C:\RAMDetect Admin\RAMDetect_RUNTIME.env"
```

Confirm admin token is configured:

```powershell
[Environment]::GetEnvironmentVariable("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", "User")
```

If RAMDetect does not detect new environment variables, close and reopen the app. If needed, restart PowerShell or restart the workstation.

## 13. Token Security

Do not commit or share:

```text
RAMDETECT_REPOSITORY_API_TOKEN
RAMDETECT_REPOSITORY_ADMIN_API_TOKEN
RAMDETECT_DB_URL with real password
RAMDetect_RUNTIME.env
RAM dumps
Generated reports
Activity/history databases
```

If a real token is exposed, regenerate it before final deployment or demonstration.

## 14. Recommended Deployment Practice

Use a static DHCP reservation or stable hostname for the PTM/Admin server. This avoids repeated reconfiguration when the server IP changes.

Example hostname-based configuration:

```powershell
.\Configure_RAMDetect_Admin_Server.ps1 `
  -ServerIP "THUNDERJACK" `
  -ClientToken "<CLIENT_UPLOAD_TOKEN>" `
  -AdminToken "<ADMIN_TOKEN>"
```

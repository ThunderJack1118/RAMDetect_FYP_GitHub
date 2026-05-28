# RAMDetect Analyst Client Deployment Guide

## 1. Purpose

RAMDetect Analyst Client is the normal workstation version of RAMDetect. It is used by analysts to import or acquire RAM dumps, run post-incident RAM forensic analysis, review machine-learning results, export reports, and upload activity/report records to the PTM Repository Server when Online Mode is available.

RAMDetect is a post-incident RAM forensics triage tool. It is not an antivirus, EDR, or real-time malware blocker.

## 2. Installation Path

Default installation path:

```text
C:\RAMDetect Analyst
```

Main executable:

```text
C:\RAMDetect Analyst\RAMDetect.exe
```

## 3. Analyst Access Rule

The Analyst Client must not contain the PTM repository admin token.

Expected analyst configuration:

```text
RAMDETECT_REPOSITORY_ADMIN_API_TOKEN=
```

If an Admin account is used on an Analyst workstation, RAMDetect blocks the Admin login when the admin token is missing. This prevents an Analyst installation from being used to access Admin Management or central repository download functions.

## 4. Configure Server Connection

When the PTM server IP changes, run the included configuration script:

```powershell
cd "C:\RAMDetect Analyst"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\Configure_RAMDetect_Analyst_Server.ps1 `
  -ServerIP "192.168.1.36" `
  -ClientToken "<CLIENT_UPLOAD_TOKEN>"
```

After running the script, close and reopen RAMDetect.

The script writes both Windows user environment variables and a local runtime file:

```text
C:\RAMDetect Analyst\RAMDetect_RUNTIME.env
```

The local runtime file helps RAMDetect read the latest server settings even when Windows environment variables have not refreshed yet.

## 5. Required PTM Services

Online Mode requires:

```text
PostgreSQL RAMDetect shared database
PTM Repository Server API
Client upload token
```

The PTM Server API should be reachable from the analyst workstation, for example:

```powershell
Invoke-RestMethod http://192.168.1.36:8765/health
```

## 6. Runtime Mode

Recommended mode:

```powershell
setx RAMDETECT_RUNTIME_MODE "auto"
```

Auto mode allows RAMDetect to use Online Mode when the PTM server is reachable and Offline Local Mode when the server is unavailable.

## 7. Analyst Workflow

Typical analyst workflow:

```text
1. Login as Analyst.
2. Import or acquire a RAM dump.
3. Confirm dump metadata and DTB status.
4. Select analysis modules.
5. Run Real-Time Analysis.
6. Review Results Dashboard, Artifact Viewer, and ML Insights.
7. Export PDF, JSON, or XLSX reports.
8. Upload activity/report records when Online Mode is available.
```

## 8. Supported Displayed Dump Extensions

The Acquisition page displays these accepted RAM dump formats:

```text
.dmp · .mem · .raw
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

The deployed client includes a bundled Volatility runner for the two documented Volatility-assisted exceptions:

```text
windows.info.Info  - DTB / OS profile / architecture metadata support
windows.handles    - handle enumeration support
```

These functions support artifact extraction and metadata resolution only. They do not override the final ML verdict.

If `windows.handles` fails or times out, RAMDetect continues analysis without handle artifacts.

## 11. Machine Learning Runtime

The packaged Analyst Client uses the NumPy Autoencoder runtime file:

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

Check analyst runtime file:

```powershell
Get-Content "C:\RAMDetect Analyst\RAMDetect_RUNTIME.env"
```

If RAMDetect does not detect new environment variables, close and reopen the app. If needed, restart PowerShell or restart the workstation.

## 13. Security Notes

Do not store the admin token on the Analyst workstation.

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

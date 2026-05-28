# RAMDetect

**RAMDetect: A Machine Learning-Based RAM Forensics Analysis for Post-Incident Using DumpIt Acquisition**

RAMDetect is a Windows desktop RAM forensics triage tool for post-incident analysis. It acquires or imports RAM dumps, extracts memory artifacts, maps live features into the CIC-MalMem2022 feature schema, and classifies a dump as **CLEAN** or **SUSPICIOUS** using an ML-only RF-AE feature-fusion pipeline.

RAMDetect also supports PTM-style multi-workstation deployment through role-based login, Activity Monitor, Admin Management, PostgreSQL-backed activity storage, and a PTM Central Report Repository API. Analyst workstations automatically upload activity events and generated reports to the central server; the admin workstation can monitor those events and download reports without manually collecting files from each PC.

---

## Key Features

- **RAM acquisition and import**
  - Live RAM acquisition through DumpIt.
  - Existing memory dump import for post-incident analysis.
  - Portable dump/session output under the current RAMDetect folder.

- **Custom RAM artifact extraction**
  - Process, thread, DLL/LDR, VAD, PE section, service, handle, and injection-related artifacts.
  - RAMDetect-native parsing where feasible.
  - Two documented Volatility-assisted exceptions only: handle enumeration and DTB/OS metadata resolution.

- **ML-only RF-AE detection**
  - 54 CIC-MalMem canonical memory-forensics features.
  - Autoencoder reconstruction MSE appended as the 55th fused feature.
  - Random Forest classifier produces the final verdict.
  - Fixed RF threshold: `0.50`.

- **No rule-based verdict override**
  - No forensic veto rules.
  - No clean dampeners.
  - No deterministic suspicious override.
  - Report-only indicators do not change the ML result.

- **Activity Monitor and Admin Management**
  - Login history, analysis history, file access, report history, and full audit trail.
  - User account management and workstation registration/trust/block controls.
  - Central activity auto-sync from analyst workstations to PTM server.

- **Strict PTM central report repository**
  - Staff/analyst clients upload reports using an upload-only client token.
  - Admin clients list/open/download reports using an admin token.
  - PTM server stores repository metadata and physical report files centrally.

- **Offline Local Mode**
  - Startup checks PostgreSQL and PTM server connectivity before loading the GUI.
  - If the local PostgreSQL service `postgresql-x64-18` is stopped on the server/admin workstation, RAMDetect attempts to start it automatically.
  - If PostgreSQL is still unavailable, RAMDetect bypasses central login and opens an Analyst-level local interface for acquisition, analysis, artifact review, and local report export.
  - Admin Management, central Activity Monitor, PTM repository upload/download, and central activity sync remain disabled while offline.

---

## Current Architecture Summary

```text
Admin/PTM Server Workstation
    ├── PostgreSQL database on port 5432
    │   └── users, workstations, login history, audit logs, analysis sessions, reports
    ├── PTM Repository API on port 8765
    │   ├── report upload/list/download
    │   └── central activity event upload/list
    └── RAMDetect admin client
        ├── Activity Monitor
        ├── Admin Management
        └── central report download

Analyst/Staff Workstation
    └── RAMDetect analyst client
        ├── connects to shared PostgreSQL database
        ├── uploads activity events to PTM API using client token
        ├── uploads exported reports to PTM API using client token
        └── does not receive the admin token

RAM analysis workflow
    ├── DumpIt live acquisition or existing dump import
    ├── dump validation and metadata/DTB/profile preparation
    ├── custom parser pipeline
    ├── feature extraction and aggregation
    ├── FeatureMapper to 54 CIC-MalMem canonical features
    ├── Autoencoder reconstruction MSE
    ├── 55-feature fused vector: 54 features + AE MSE
    └── Random Forest final verdict with threshold 0.50
```

The monitoring/database/repository components store metadata and reports only. They do **not** control or override the ML verdict.

### Startup Connectivity and Offline Local Mode

When RAMDetect starts, it performs a short runtime connectivity check before deciding whether to show the normal central login flow or the local fallback workflow.

```text
RAMDetect startup
    ├── Check RAMDETECT_DB_URL / PostgreSQL SELECT 1
    ├── If local PostgreSQL service postgresql-x64-18 is stopped:
    │       └── try Start-Service postgresql-x64-18 and wait for database readiness
    ├── If PostgreSQL becomes reachable:
    │       └── normal online login mode
    └── If PostgreSQL remains unreachable:
            └── Offline Local Mode
                    ├── bypass central login
                    ├── open as Local Analyst
                    ├── allow local acquisition/import, analysis, artifact viewing, ML insights, and local report export
                    └── disable Admin Management, central Activity Monitor, PTM repository upload/download, and central activity sync
```

Offline Local Mode is a runtime availability fallback only. It does not change the parser output, FeatureMapper, Autoencoder MSE fusion, Random Forest threshold, or ML-only final verdict.

---

## ML Decision Policy

RAMDetect uses an RF-AE feature-fusion design:

```text
54 canonical CIC-MalMem features
        ↓
Autoencoder reconstructs the 54-feature vector
        ↓
Reconstruction MSE is calculated
        ↓
54 canonical features + AE MSE = 55 fused RF input
        ↓
Random Forest suspicious probability
        ↓
P(Suspicious) >= 0.50 → SUSPICIOUS
P(Suspicious) <  0.50 → CLEAN
```

Important constraints:

```text
- Final verdict is ML-only.
- RF threshold remains fixed at 0.50.
- Autoencoder MSE is a fused input feature, not a separate override.
- Parser evidence may become features/report evidence but cannot force a verdict.
- Activity logs and report repository metadata cannot affect classification.
```

---

## Volatility Policy

RAMDetect should not be described as a Volatility-wrapper system. The current implemented policy is:

```text
Custom/native RAM parsing is used where feasible.
Volatility-assisted support is limited to two documented exceptions:
1. windows.handles for handle enumeration.
2. windows.info.Info for DTB / OS profile / architecture metadata resolution.
```

These exceptions are engineering limitations and future-work targets. They do not modify FeatureMapper, Autoencoder MSE fusion, Random Forest threshold, or the final RF-AE verdict.

---

## Project Structure

```text
RAMDetect/
├── main.py
├── config.yaml
├── requirements.txt
├── datasets/
├── dumps/                         # managed imported/acquired dumps and sidecar JSON
├── logs/
├── models/
├── reports/                       # local generated report/export output
├── tools/
│   └── DumpIt.exe
└── ramdetect/
    ├── acquisition/
    ├── case_management/
    │   ├── activity_logger.py
    │   ├── auth_service.py
    │   ├── database.py
    │   ├── init_db.py
    │   ├── models.py
    │   ├── report_record_service.py
    │   ├── report_repository.py
    │   ├── user_service.py
    │   └── workstation_service.py
    ├── extraction/
    ├── features/
    ├── ml/
    ├── reporting/
    ├── ui/
    │   ├── case_management_integration.py
    │   ├── bridge/
    │   │   ├── acquisition_bridge.py
    │   │   ├── config_bridge.py
    │   │   └── auth_bridge.py
    │   ├── pages/
    │   │   ├── login.py
    │   │   ├── dashboard.py
    │   │   ├── activity_monitor.py
    │   │   ├── admin_management.py
    │   │   ├── acquisition.py
    │   │   ├── results_dashboard.py
    │   │   ├── artifacts_viewer.py
    │   │   ├── reports.py
    │   │   └── settings.py
    │   ├── resources/
    │   └── widgets/
    └── utils/
```

Strict PTM deployment uses a separate server folder:

```text
RAMDetect_PTM_Server/
├── ptm_report_repository_server.py
├── start_ptm_server.ps1
├── requirements_repository_server.txt
└── README_PTM_STRICT_DEPLOYMENT.md

RAMDetect_PTM_ReportRepository/
├── repository.db
└── reports/<date>/<workstation>/<username>/
```

---

## Portable Path Rule

RAMDetect is designed so the project folder can be copied to another workstation without writing back to the old source folder.

Current rule:

```text
Imported/acquired dumps → <current RAMDetect folder>/dumps/<session>/
Generated reports       → <current RAMDetect folder>/reports/
Artifact exports        → <current RAMDetect folder>/reports/<dump/session>/
```

The acquisition bridge prevents external JSON sidecar pollution. When a dump is imported from another directory, RAMDetect should not create JSON beside the original source file.

Expected behavior:

```text
✅ C:\Users\annsi\Downloads\RAMDetect\dumps\<session>\VMTJ-20260411-152425.dmp
✅ C:\Users\annsi\Downloads\RAMDetect\dumps\<session>\VMTJ-20260411-152425.json
❌ C:\Users\annsi\Downloads\VMTJ-20260411-152425.json
❌ C:\Users\annsi\Downloads\GITHUB\RAMDetect\dumps\...
```

---

## Admin/PTM Server Setup

This setup is required when more than one workstation needs to share activity logs and reports.

### 1. Install PostgreSQL on the server workstation

Install PostgreSQL on the machine that will act as the PTM/admin server. Other analyst workstations do **not** need PostgreSQL Server installed.

Create the RAMDetect database and application user:

```sql
CREATE USER ramdetect_app WITH PASSWORD 'changeme';
CREATE DATABASE ramdetect_db OWNER ramdetect_app;
GRANT ALL PRIVILEGES ON DATABASE ramdetect_db TO ramdetect_app;

\c ramdetect_db

GRANT ALL ON SCHEMA public TO ramdetect_app;
ALTER SCHEMA public OWNER TO ramdetect_app;
```

For real deployment, replace `changeme` with a stronger password and update all client connection strings.

### 2. Allow PostgreSQL remote client access

Edit PostgreSQL `postgresql.conf` on the server:

```text
listen_addresses = '*'
```

Edit `pg_hba.conf` and allow the PTM workstation subnet, for example:

```text
host    ramdetect_db    ramdetect_app    172.20.10.0/24    scram-sha-256
```

Restart PostgreSQL:

```powershell
Restart-Service postgresql-x64-18
```

Open the Windows Firewall port:

```powershell
New-NetFirewallRule -DisplayName "RAMDetect PostgreSQL 5432" -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Allow
```

Recommended service startup setting on the PTM/admin server:

```powershell
Set-Service postgresql-x64-18 -StartupType Automatic
Start-Service postgresql-x64-18
Get-Service postgresql-x64-18 | Select Name, Status, StartType
```

RAMDetect also includes a startup fallback that attempts to start `postgresql-x64-18` automatically when it is stopped. This automatic start requires the application to be launched with Administrator privileges. If the service cannot be started or PostgreSQL still rejects the connection, RAMDetect continues in Offline Local Mode instead of closing.

### 3. Initialize RAMDetect database tables

From the admin/server RAMDetect folder:

```powershell
cd C:\RAMDetect
.\venv\Scripts\Activate.ps1
python -m ramdetect.case_management.init_db
```

Default demo accounts:

```text
admin / admin123      role: Admin
analyst / analyst123  role: Analyst
```


### Recommended: Use the PTM startup script

The PTM server folder includes:

```text
start_ptm_server.ps1
```

This PowerShell script simplifies PTM Repository API startup.

Run:

```powershell
cd C:\RAMDetect_PTM_Server
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\start_ptm_server.ps1
```

The script is intended to automate PTM server startup tasks such as:

- activating the Python virtual environment
- loading repository environment variables
- launching uvicorn
- preparing repository folders

If the script is unavailable or needs customization, the PTM Repository API can still be started manually using the uvicorn command below.

### 4. Start PTM Repository API

On the server workstation:

```powershell
cd C:\RAMDetect_PTM_Server
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements_repository_server.txt

$env:RAMDETECT_PTM_REPOSITORY_ROOT = "C:\RAMDetect_PTM_ReportRepository"
$env:RAMDETECT_PTM_REPOSITORY_DB = "C:\RAMDetect_PTM_ReportRepository\repository.db"
$env:RAMDETECT_REPOSITORY_ADMIN_TOKEN = "<0BB71222D97491E9A36ED3270876238617907FA5747D00824CFA21583F289369>"
$env:RAMDETECT_REPOSITORY_CLIENT_TOKEN = "<47E0E97E0C43756EE7636F55A0010A8A51339430DBA403C14849F02DC3767DDE>"

uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765
```

Open the firewall port:

```powershell
New-NetFirewallRule -DisplayName "RAMDetect PTM API 8765" -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow
```

Health check from the server:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
Invoke-RestMethod http://<PTM_SERVER_IP>:8765/health
```

Expected:

```text
status: ok
tokens_configured: True
```

---

## Easy Setup: Analyst Workstation Client

Use these steps when copying RAMDetect to another staff/analyst PC.

### 1. Copy the RAMDetect client folder

Copy the RAMDetect source/client folder to any location, for example:

```text
C:\Users\<User>\Downloads\RAMDetect
```

It does not need to be inside a GitHub folder. The folder only needs to contain:

```text
main.py
requirements.txt
config.yaml
ramdetect\
models\
tools\DumpIt.exe
```

### 2. Install Python 3.10

Install Python 3.10.x on the analyst workstation. During installation, enable:

```text
Add python.exe to PATH
Install launcher for all users
```

Do not use Python 3.14 for this project because some pinned scientific/ML packages may not have compatible wheels.

### 3. Create and activate virtual environment

```powershell
cd "C:\Users\<User>\Downloads\RAMDetect"
py -3.10 -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
python --version
```

Expected:

```text
Python 3.10.x
```

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Configure shared server connection

Replace `<PTM_SERVER_IP>` with the admin/server workstation IP address.

```powershell
setx RAMDETECT_DB_URL "postgresql+psycopg2://ramdetect_app:changeme@<PTM_SERVER_IP>:5432/ramdetect_db"
setx RAMDETECT_REPOSITORY_API_URL "http://<PTM_SERVER_IP>:8765"
setx RAMDETECT_REPOSITORY_API_TOKEN "<CLIENT_UPLOAD_TOKEN>"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN ""
```

Close and reopen PowerShell after `setx`.

### 6. Verify the analyst client connection

```powershell
cd "C:\Users\<User>\Downloads\RAMDetect"
.\venv\Scripts\Activate.ps1

python -c "from sqlalchemy import create_engine; import os; print(os.getenv('RAMDETECT_DB_URL')); e=create_engine(os.getenv('RAMDETECT_DB_URL')); print(e.connect().exec_driver_sql('SELECT 1').scalar())"

Invoke-RestMethod http://<PTM_SERVER_IP>:8765/health
```

Expected:

```text
1
status: ok
```

### 7. Run RAMDetect

```powershell
python main.py
```

Login as:

```text
analyst / analyst123
```

The analyst client should be able to import/analyze dumps and export reports. It should not have the admin token.

---

## Admin Workstation Setup

The admin workstation can be the same as the PTM server workstation or a separate machine.

Set both client and admin repository tokens:

```powershell
setx RAMDETECT_DB_URL "postgresql+psycopg2://ramdetect_app:changeme@<PTM_SERVER_IP>:5432/ramdetect_db"
setx RAMDETECT_REPOSITORY_API_URL "http://<PTM_SERVER_IP>:8765"
setx RAMDETECT_REPOSITORY_API_TOKEN "<CLIENT_UPLOAD_TOKEN>"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN "<ADMIN_TOKEN>"
```

Admin users can:

```text
- view Activity Monitor records from all connected workstations
- manage users and workstations
- list/open/download reports from the PTM repository
- trigger REPORT_DOWNLOADED audit records
```

---

## Central Activity Auto-Sync

Each RAMDetect client automatically records application activity and sends it to the PTM Repository API.

Tracked examples:

```text
APP_OPENED
LOGIN_SUCCESS
LOGIN_FAILED
LOGOUT
APP_CLOSED
DUMP_SELECTED
DUMP_IMPORTED
ANALYSIS_STARTED
ANALYSIS_COMPLETED
PDF_EXPORTED
JSON_EXPORTED
CSV_EXPORTED
XLSX_EXPORTED
WORKBOOK_EXPORTED
REPORT_GENERATED
REPORT_DOWNLOADED
```

Central sync behavior:

```text
ActivityLogger writes local/shared DB audit record
        +
ActivityLogger uploads the event to POST /api/v1/activity/upload
        ↓
PTM server stores it in repository.db activity_events
        ↓
Admin Activity Monitor lists it using GET /api/v1/activity
```

The user does not manually input log records. RAMDetect captures them automatically when actions happen.

---

## Different-Workstation Proof Checklist

Use this checklist to prove central monitoring across two workstations.

```text
Workstation 1: Admin/PTM server
- PostgreSQL running on 5432
- PTM Repository API running on 8765
- RAMDetect admin account logged in

Workstation 2: Analyst client
- RAMDetect copied to a local folder
- Python 3.10 venv installed
- DB URL points to Workstation 1 IP
- PTM API URL points to Workstation 1 IP
- Client token is set
- Admin token is empty
```

Evidence to capture:

```text
1. Workstation 2 hostname command output.
2. Workstation 2 analyst login/running analysis.
3. Workstation 1 Activity Monitor → Login History showing analyst and Workstation 2 hostname.
4. Workstation 1 Activity Monitor → Analysis History showing analysis completed by analyst.
5. Workstation 1 Activity Monitor → Report History showing analyst PDF/XLSX export with ramdetect-api:// path.
6. Workstation 1 Activity Monitor → File Access showing analyst export and admin report download.
7. Workstation 1 Activity Monitor → Full Audit Trail showing login → dump import → analysis → export → admin download.
8. Workstation 1 Admin Management → PC/Workstation List showing Workstation 2 registered.
```

Verified proof example from testing:

```text
Admin workstation: ThunderJack
Analyst workstation: DESKTOP-IBHMHPE
Workstation ID: 2
Observed actions: Login Success, Dump Imported, Analysis Started, Analysis Completed, PDF Exported, Report Downloaded
```

---

## Troubleshooting


### PowerShell says scripts are disabled

Windows PowerShell may block `.ps1` files by default.

Temporary bypass for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then run:

```powershell
.\start_ptm_server.ps1
```

### PowerShell blocks Activate.ps1

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

### Python package install fails on Workstation 2

Use Python 3.10.x and recreate the virtual environment:

```powershell
Remove-Item venv -Recurse -Force
py -3.10 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### PostgreSQL connection refused

Check PostgreSQL service and firewall on the server:

```powershell
Get-Service *postgres*
Test-NetConnection <PTM_SERVER_IP> -Port 5432
```

### `no pg_hba.conf entry`

Add the client subnet to `pg_hba.conf` on the PostgreSQL server. For example:

```text
host    ramdetect_db    ramdetect_app    172.20.10.0/24    scram-sha-256
host    ramdetect_db    ramdetect_app    192.168.1.0/24    scram-sha-256
```

Use the subnet that matches the client IP address. For example, if the client/server IP is `192.168.1.36`, the `192.168.1.0/24` rule allows RAMDetect workstations on the same LAN. Restart PostgreSQL after editing:

```powershell
Restart-Service postgresql-x64-18
```

### PTM API unreachable

Make sure the server is started with network binding:

```powershell
uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765
```

Check firewall:

```powershell
New-NetFirewallRule -DisplayName "RAMDetect PTM API 8765" -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow
```

### Client still writes to old folder

Check `config.yaml`. Project-owned paths should be relative:

```yaml
acquisition:
  dumpit_path: tools/DumpIt.exe
  output_dir: dumps
paths:
  reports_dir: reports/
  dumps_dir: dumps/
```

RAMDetect should write to the current project folder, not an old copied path.

---

## Useful Commands

Verify repository tokens loaded by RAMDetect:

```powershell
python -c "import os; print('DB=', os.getenv('RAMDETECT_DB_URL')); print('API=', os.getenv('RAMDETECT_REPOSITORY_API_URL')); print('CLIENT_TOKEN=', bool(os.getenv('RAMDETECT_REPOSITORY_API_TOKEN'))); print('ADMIN_TOKEN=', bool(os.getenv('RAMDETECT_REPOSITORY_ADMIN_API_TOKEN')))"
```

Syntax check selected files:

```powershell
python -m py_compile `
  ramdetect\case_management\activity_logger.py `
  ramdetect\case_management\report_repository.py `
  ramdetect\ui\pages\activity_monitor.py `
  ramdetect\ui\bridge\acquisition_bridge.py `
  ramdetect\ui\bridge\config_bridge.py
```

Verify PTM activity events from repository database:

```powershell
cd C:\RAMDetect_PTM_ReportRepository
python check_ptm_repository.py
```

---

## Validation Checklist

Before final demonstration, verify:

```text
Admin login works.
Analyst login works.
Analyst cannot access Admin Management.
PostgreSQL shared DB connection works from analyst workstation.
PTM API health check works from analyst workstation.
PostgreSQL service auto-start works when running RAMDetect as Administrator on the server/admin workstation.
If PostgreSQL is stopped/unreachable, RAMDetect opens Offline Local Mode instead of crashing.
Offline Local Mode bypasses login and opens the Analyst-level local interface only.
Offline Local Mode disables Admin Management, central Activity Monitor, PTM upload/download, and central activity sync.
Clean dump remains CLEAN.
Suspicious dump becomes SUSPICIOUS.
Reports export successfully.
Exports upload to PTM repository when configured.
Activity events upload to PTM repository when configured.
Admin can monitor analyst-created activity from another workstation.
Admin can download analyst-created report.
REPORT_DOWNLOADED appears in Full Audit Trail.
Activity Monitor XLSX export works.
Imported dumps and JSON sidecars remain inside current RAMDetect/dumps/<session>/.
No ML threshold/rule override is introduced.
```

---

## Academic Scope

RAMDetect is intended for academic/FYP and controlled post-incident RAM forensics triage. It is not a live EDR/antivirus replacement. The tool supports analyst review through memory artifacts, ML classification, centralized accountability logs, and admin-controlled report access, but final operational conclusions should still be reviewed by a human analyst.

---

## License and Sensitive Data Notice

Do not commit real tokens, passwords, memory dumps, forensic reports, or sensitive PTM/user data to public repositories. Use private repositories and sanitize screenshots before submission.

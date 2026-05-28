# RAMDetect Deployment Patch

This patch adds the first deployment structure for RAMDetect:

- PyInstaller onedir executable build
- Analyst and Admin Inno Setup installer scripts
- Analyst/Admin environment setup scripts
- Sanitized PTM Server package script
- Converted `ramdetect.ico`
- GitHub-safe `.gitignore`

## Important cleanup before GitHub

Remove or exclude these before the first private GitHub commit:

```text
venv/
.venv/
venvvenv/
RAMDetect_PTM_Server/.venv/
RAMDetect_PTM_ReportRepository/repository.db
RAMDetect_PTM_ReportRepository/reports/
dumps/
reports/
logs/
*.dmp, *.raw, *.mem, *.vmem
real-token startup scripts
```

## Required config patch

Your uploaded client still had this stale path:

```yaml
acquisition:
  output_dir: C:/Users/annsi/Downloads/GITHUB/RAMDetect/dumps
```

Patch it to:

```yaml
acquisition:
  output_dir: dumps
```

This preserves the RAMDetect portable path rule.

## Build executable

Run on Windows from RAMDetect project root:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build\build_exe.ps1
```

Expected output:

```text
dist\RAMDetect\RAMDetect.exe
```

## Build installers

Install Inno Setup, then run:

```powershell
cd installer
iscc .\RAMDetect_Analyst.iss
iscc .\RAMDetect_Admin.iss
```

Expected output:

```text
installer\output\RAMDetect_Analyst_Setup.exe
installer\output\RAMDetect_Admin_Setup.exe
```

## Build sanitized PTM server zip

Run from the folder that contains `RAMDetect_PTM_Server`:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\RAMDetect\deployment\package_ptm_server.ps1 `
  -ServerFolder ".\RAMDetect_PTM_Server" `
  -OutputZip ".\release\RAMDetect_PTM_Server.zip"
```

Do not package `.venv`, `repository.db`, or generated report files.

# RAMDetect PyInstaller Build Fix — Python 3.10.0

## Problem

The RAMDetect build reaches PyInstaller analysis and fails with:

```text
IndexError: tuple index out of range
PyInstaller output not found: dist\RAMDetect\RAMDetect.exe
```

The build log shows:

```text
Python 3.10.0
PyInstaller: 6.20.0
```

PyInstaller does not support Python 3.10.0 because of a CPython bug. Use Python 3.10.11 x64 instead.

## Fix

Run these commands from a normal, non-Administrator PowerShell terminal:

```powershell
cd "C:\Users\annsi\Downloads\RAMDetect_Client_Package"

# Leave any active venv first
if ($env:VIRTUAL_ENV) { deactivate }

# Clean failed build environment
Remove-Item .venv-build -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item build\RAMDetect -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item dist -Recurse -Force -ErrorAction SilentlyContinue

# Verify Python launcher after installing Python 3.10.11
py -0p
py -3.10 -c "import sys; print(sys.version)"

# Build again
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build\build_exe.ps1
```

Expected Python output should start with:

```text
3.10.11
```

Expected build output:

```text
dist\RAMDetect\RAMDetect.exe
```

## Important

Do not run the build from inside the old RAMDetect development venv. Build from the client package root and let `.venv-build` be recreated.

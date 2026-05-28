# RAMDetect PyInstaller Keras Wrapper Crash Fix

## Problem
The first build spec collected every submodule from `keras`, `sklearn`, `pandas`, `reportlab`, and `volatility3`. This made PyInstaller scan unused test modules and Keras wrappers. The build then crashed during binary dependency discovery:

```text
SubprocessDiedError: Child process died calling import_library() with args=('keras.wrappers',)
```

## Fix
Replace:

```text
build\RAMDetect.spec
```

with the fixed version in this patch, then rebuild from a normal PowerShell terminal:

```powershell
cd "C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"

Remove-Item ".venv-build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "dist" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "build\RAMDetect" -Recurse -Force -ErrorAction SilentlyContinue

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build\build_exe.ps1
```

This spec keeps TensorFlow/Keras runtime imports but excludes unused Keras wrappers, Torch/JAX/OpenVINO backends, package test suites, and non-Windows Volatility plugin groups.

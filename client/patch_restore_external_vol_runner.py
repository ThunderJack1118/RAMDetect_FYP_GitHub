from pathlib import Path
import re
import shutil
from datetime import datetime

ROOTS = [
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect"),
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"),
]

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

VOL_RESOLVER = r'''
def _resolve_volatility_exe() -> str | None:
    """Resolve Volatility CLI in development and installed PyInstaller mode."""
    import sys as _sys
    import shutil as _shutil
    from pathlib import Path as _Path

    candidates = []

    # Installed / PyInstaller onedir mode: bundled console Volatility runner.
    try:
        exe_dir = _Path(_sys.executable).resolve().parent
        candidates.append(exe_dir / "_internal" / "tools" / "vol.exe")
        candidates.append(exe_dir / "tools" / "vol.exe")
    except Exception:
        pass

    try:
        meipass = getattr(_sys, "_MEIPASS", None)
        if meipass:
            candidates.append(_Path(meipass) / "tools" / "vol.exe")
    except Exception:
        pass

    # Development mode: normal venv/PATH command.
    for item in (_shutil.which("vol"), _shutil.which("vol.exe")):
        if item:
            candidates.append(_Path(item))

    # Source fallback: project tools folder.
    try:
        here = _Path(__file__).resolve()
        for parent in [here.parent, *here.parents]:
            candidates.append(parent / "tools" / "vol.exe")
    except Exception:
        pass

    try:
        candidates.append(_Path.cwd() / "tools" / "vol.exe")
    except Exception:
        pass

    for candidate in candidates:
        try:
            if candidate and candidate.exists():
                return str(candidate)
        except Exception:
            continue

    return None

'''

def backup(path: Path):
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + f".bak-vol-clean-{STAMP}"))

def patch_main(root: Path):
    path = root / "main.py"
    if not path.exists():
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    # Remove internal RAMDetect.exe-as-volatility-cli function.
    text = re.sub(
        r'\ndef _maybe_run_internal_volatility_cli\(\).*?(?=\ndef main\()',
        '\n',
        text,
        flags=re.S
    )

    # Remove call at start of main().
    text = re.sub(
        r'(\ndef main\([^)]*\):\n)\s*_maybe_run_internal_volatility_cli\(\)\n',
        r'\1',
        text
    )

    path.write_text(text, encoding="utf-8")
    print(f"[OK] Cleaned internal CLI mode from: {path}")

def patch_resolver(root: Path):
    rels = [
        r"ramdetect\extraction\parsers\handle_parser.py",
        r"ramdetect\acquisition\metadata_reader.py",
        r"ramdetect\utils\find_dtb.py",
        r"ramdetect\ui\bridge\acquisition_bridge.py",
    ]

    for rel in rels:
        path = root / rel
        if not path.exists():
            print(f"[SKIP] Missing: {path}")
            continue

        backup(path)
        text = path.read_text(encoding="utf-8")

        if "def _resolve_volatility_exe()" in text:
            text = re.sub(
                r"def _resolve_volatility_exe\(\).*?(?=\ndef |\nclass |\Z)",
                VOL_RESOLVER.strip() + "\n",
                text,
                count=1,
                flags=re.S
            )
        else:
            if "def _hidden_subprocess_kwargs()" in text:
                text = text.replace("def _hidden_subprocess_kwargs()", VOL_RESOLVER + "\ndef _hidden_subprocess_kwargs()", 1)
            else:
                imports = list(re.finditer(r"^(import .+|from .+ import .+)$", text, flags=re.M))
                if imports:
                    end = imports[-1].end()
                    text = text[:end] + "\n\n" + VOL_RESOLVER + text[end:]
                else:
                    text = VOL_RESOLVER + text

        text = text.replace('shutil.which("vol") or shutil.which("vol.exe")', '_resolve_volatility_exe()')
        text = text.replace("shutil.which('vol') or shutil.which('vol.exe')", "_resolve_volatility_exe()")
        text = text.replace('shutil.which("vol.exe") or shutil.which("vol")', '_resolve_volatility_exe()')
        text = text.replace("shutil.which('vol.exe') or shutil.which('vol')", "_resolve_volatility_exe()")

        path.write_text(text, encoding="utf-8")
        print(f"[OK] Patched resolver: {path}")

for root in ROOTS:
    print("=" * 70)
    print(f"[RAMDetect] Patching root: {root}")
    patch_main(root)
    patch_resolver(root)

print("=" * 70)
print("[RAMDetect] Volatility resolver cleanup complete.")

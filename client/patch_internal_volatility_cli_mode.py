from pathlib import Path
import re
import shutil
from datetime import datetime

ROOTS = [
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect"),
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"),
]

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

INTERNAL_VOL_FUNC = r'''
def _maybe_run_internal_volatility_cli() -> None:
    """Allow frozen RAMDetect.exe to behave like: vol -f <dump> windows.info.Info/windows.handles."""
    argv = sys.argv[1:]
    allowed_plugins = {"windows.info.Info", "windows.handles"}

    if "-f" not in argv:
        return
    if not any(arg in allowed_plugins for arg in argv):
        return

    # Prevent GUI startup. Execute Volatility CLI using the bundled volatility3 package.
    from volatility3.cli import main as _volatility_main
    raise SystemExit(_volatility_main())

'''

VOL_RESOLVER = r'''
def _resolve_volatility_exe() -> str | None:
    """Resolve Volatility command in dev mode and installed PyInstaller mode."""
    import sys as _sys
    import shutil as _shutil
    from pathlib import Path as _Path

    # In installed/frozen mode, RAMDetect.exe itself acts as the Volatility CLI.
    try:
        if getattr(_sys, "frozen", False):
            return str(_Path(_sys.executable).resolve())
    except Exception:
        pass

    # In development mode, use the normal venv PATH command: vol -f ...
    for item in (_shutil.which("vol"), _shutil.which("vol.exe")):
        if item:
            return item

    # Source fallback: tools\vol.exe if manually provided.
    try:
        here = _Path(__file__).resolve()
        for parent in [here.parent, *here.parents]:
            candidate = parent / "tools" / "vol.exe"
            if candidate.exists():
                return str(candidate)
    except Exception:
        pass

    return None

'''

def backup(path: Path):
    shutil.copy2(path, path.with_suffix(path.suffix + f".bak-internal-vol-{STAMP}"))

def patch_main(root: Path):
    path = root / "main.py"
    if not path.exists():
        print(f"[SKIP] Missing main.py: {path}")
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    if "_maybe_run_internal_volatility_cli" not in text:
        m = re.search(r"^def main\([^)]*\):\s*\n", text, flags=re.M)
        if not m:
            print(f"[ERROR] Cannot find def main() in {path}")
            return

        text = text[:m.start()] + INTERNAL_VOL_FUNC + "\n" + text[m.start():]

    # Call it at the very start of main().
    if "_maybe_run_internal_volatility_cli()" not in text.split("def main", 1)[1][:500]:
        text = re.sub(
            r"^def main\(([^)]*)\):\s*\n",
            r"def main(\1):\n    _maybe_run_internal_volatility_cli()\n",
            text,
            count=1,
            flags=re.M
        )

    path.write_text(text, encoding="utf-8")
    print(f"[OK] Patched internal Volatility CLI mode: {path}")

def patch_vol_resolver(root: Path):
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

        # Add/replace resolver.
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

        # Replace old PATH-only resolver.
        text = text.replace('shutil.which("vol") or shutil.which("vol.exe")', '_resolve_volatility_exe()')
        text = text.replace("shutil.which('vol') or shutil.which('vol.exe')", "_resolve_volatility_exe()")
        text = text.replace('shutil.which("vol.exe") or shutil.which("vol")', '_resolve_volatility_exe()')
        text = text.replace("shutil.which('vol.exe') or shutil.which('vol')", "_resolve_volatility_exe()")

        path.write_text(text, encoding="utf-8")
        print(f"[OK] Patched Volatility resolver: {path}")

for root in ROOTS:
    print("=" * 70)
    print(f"[RAMDetect] Patching root: {root}")
    patch_main(root)
    patch_vol_resolver(root)

print("=" * 70)
print("[RAMDetect] Internal Volatility CLI patch complete.")

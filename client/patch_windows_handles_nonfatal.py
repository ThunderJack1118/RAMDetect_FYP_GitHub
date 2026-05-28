from pathlib import Path
import re
import shutil
from datetime import datetime

ROOTS = [
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect"),
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"),
]

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

for root in ROOTS:
    path = root / "ramdetect" / "extraction" / "parsers" / "handle_parser.py"

    if not path.exists():
        print(f"[SKIP] Missing: {path}")
        continue

    shutil.copy2(path, path.with_suffix(path.suffix + f".bak-handles-nonfatal-{STAMP}"))

    text = path.read_text(encoding="utf-8")

    # Make subprocess.run for windows.handles non-fatal.
    # 1. Ensure check=True is not used.
    text = re.sub(
        r"subprocess\.run\((?P<body>.*?windows\.handles.*?)(?:,\s*check\s*=\s*True)(?P<tail>.*?)\)",
        r"subprocess.run(\g<body>\g<tail>)",
        text,
        flags=re.S
    )

    # 2. Add a safer timeout if the parser has no explicit timeout.
    if "RAMDETECT_VOL_HANDLES_TIMEOUT" not in text:
        insert = '''
def _vol_handles_timeout(default: int = 900) -> int:
    """Timeout for windows.handles. If it times out/fails, RAMDetect continues without handle artifacts."""
    try:
        return int(os.environ.get("RAMDETECT_VOL_HANDLES_TIMEOUT", str(default)))
    except Exception:
        return default

'''
        if "def _hidden_subprocess_kwargs()" in text:
            text = text.replace("def _hidden_subprocess_kwargs()", insert + "\ndef _hidden_subprocess_kwargs()", 1)
        else:
            imports = list(re.finditer(r"^(import .+|from .+ import .+)$", text, flags=re.M))
            if imports:
                end = imports[-1].end()
                text = text[:end] + "\n\n" + insert + text[end:]
            else:
                text = insert + text

    # 3. Replace existing timeout=... in windows.handles run block with controlled timeout.
    def patch_run_block(match):
        block = match.group(0)
        if "windows.handles" not in block:
            return block

        # Ensure hidden subprocess kwargs remain.
        if "_hidden_subprocess_kwargs()" not in block:
            block = block[:-1] + "                **_hidden_subprocess_kwargs(),\n            )"

        # Normalize timeout.
        if re.search(r"timeout\s*=", block):
            block = re.sub(r"timeout\s*=\s*[^,\n\)]+", "timeout=_vol_handles_timeout()", block)
        else:
            block = block[:-1] + "                timeout=_vol_handles_timeout(),\n            )"

        return block

    text = re.sub(r"subprocess\.run\((?P<body>.*?)\n\s*\)", patch_run_block, text, flags=re.S)

    # 4. Make common Volatility exceptions return empty handle list instead of raising.
    # This is conservative: only add an outer broad fallback if not already present.
    if "windows.handles failed non-fatally" not in text:
        text = text.replace(
            "except Exception as exc:",
            '''except subprocess.TimeoutExpired as exc:
            try:
                logger.warning("windows.handles timed out after %ss; continuing without handle artifacts.", _vol_handles_timeout())
            except Exception:
                pass
            return []
        except Exception as exc:''',
            1
        )

        # Add a non-fatal marker near the first generic exception logging if possible.
        text = text.replace(
            "logger.exception(",
            "logger.warning(\"windows.handles failed non-fatally; continuing without handle artifacts: %s\", exc)\n            logger.exception(",
            1
        )

    path.write_text(text, encoding="utf-8")
    print(f"[OK] Patched windows.handles non-fatal timeout/fallback: {path}")

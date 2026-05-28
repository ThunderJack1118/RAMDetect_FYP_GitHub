"""
Phase K1 — Make validated I2G malfind evidence promotion official/default-on.

This patch keeps the dry-run/debug controls but removes the need to manually run:
    $env:RAMDETECT_ENABLE_I2F_MALFIND_PROMOTION="1"

After K1, promotion is enabled by default. Developers can still disable it with:
    $env:RAMDETECT_DISABLE_MALFIND_PROMOTION="1"

Rules preserved: fixed RF threshold, ML-only final decision, no veto rules,
no FeatureMapper/model/dataset changes.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "ramdetect" / "extraction" / "parsers" / "injection_detector.py"

OLD = "enabled = self._env_enabled('RAMDETECT_ENABLE_I2F_MALFIND_PROMOTION', '0')"
NEW = """# PHASE_K1_OFFICIAL_MALFIND_PROMOTION_DEFAULT_ON
        # I2G was validated against clean baselines and injection-like malicious dumps.
        # It is now enabled by default as RAMDetect's official parser-level evidence
        # enhancement. It still does NOT override verdicts; it only improves
        # session.injections -> malfind.* feature quality before ML classification.
        # Developer override for baseline comparison:
        #   RAMDETECT_DISABLE_MALFIND_PROMOTION=1
        disabled = self._env_enabled('RAMDETECT_DISABLE_MALFIND_PROMOTION', '0')
        enabled = not disabled"""


def patch_file(dry_run: bool = False) -> str:
    if not TARGET.exists():
        raise RuntimeError(f"Missing target file: {TARGET}")
    text = TARGET.read_text(encoding="utf-8")
    if "PHASE_K1_OFFICIAL_MALFIND_PROMOTION_DEFAULT_ON" in text:
        return f"{TARGET}: already official/default-on"
    if OLD not in text:
        raise RuntimeError(
            "Cannot find I2F/I2G environment gate. Make sure the I2F/I2G patch is applied first."
        )
    patched = text.replace(OLD, NEW, 1)
    if not dry_run:
        bak = TARGET.with_suffix(TARGET.suffix + ".bak_K1_official")
        bak.write_text(text, encoding="utf-8")
        TARGET.write_text(patched, encoding="utf-8")
    return f"{TARGET}: {'would change' if dry_run else 'changed'}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    print("Phase K1 official malfind promotion patch")
    print("Mode:", "DRY RUN" if args.dry_run else "APPLY")
    print(" ", patch_file(args.dry_run))
    print("Rules preserved: ML-only verdict, RF threshold unchanged, no veto rules.")
    print("Runtime disable override: $env:RAMDETECT_DISABLE_MALFIND_PROMOTION='1'")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

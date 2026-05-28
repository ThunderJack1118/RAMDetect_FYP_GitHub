from __future__ import annotations
# ---------------------------------------------------------------------------
# PyInstaller windowed-mode stdout/stderr guard
# ---------------------------------------------------------------------------
# In a Windows GUI build with PyInstaller console=False, sys.stdout/sys.stderr
# can be None. Some analysis helpers and third-party libraries still expect a
# writable stream during parsing/model loading.
import sys


class _RAMDetectNullWriter:
    def write(self, text):
        return len(str(text or ""))

    def flush(self):
        pass

    def isatty(self):
        return False


if sys.stdout is None:
    sys.stdout = _RAMDetectNullWriter()

if sys.stderr is None:
    sys.stderr = _RAMDetectNullWriter()

#!/usr/bin/env python3
"""
RAMDetect — ML-Powered RAM Forensics Analysis Tool
Entry point supporting GUI mode and CLI operations.

Usage:
    python main.py              # Launch GUI (default)
    python main.py --gui        # Launch GUI explicitly
    python main.py --analyze <dump.raw>
    python main.py --acquire
    python main.py --train --dataset ./datasets
    python main.py --version
"""
import argparse
import logging
import os
import sys
import textwrap
from pathlib import Path

# ── Project root on sys.path ──────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent


def _has_complete_ui_layout(base: Path) -> bool:
    """Return True only when a candidate contains the real GUI package.

    PyInstaller onedir builds may contain ramdetect/ui/resources without the
    full ramdetect/ui/widgets and ramdetect/ui/pages source tree. Checking only
    that a ui folder exists can therefore make RAMDetect choose an incomplete
    package and fail with "No module named 'ui.widgets.header_bar'".
    """
    ui_dir = base / "ui"
    return (
        (ui_dir / "main_window.py").is_file()
        and (ui_dir / "widgets" / "header_bar.py").is_file()
        and (ui_dir / "pages").is_dir()
        and (ui_dir / "bridge").is_dir()
    )


_nested = ROOT / "ramdetect"
if _has_complete_ui_layout(_nested):
    # Layout B: RAMDetect/ramdetect/ui/ — ui is inside the package dir.
    sys.path.insert(0, str(_nested))
elif _has_complete_ui_layout(ROOT):
    # Layout A: RAMDetect/ui/ — ui sits directly next to main.py.
    sys.path.insert(0, str(ROOT))
elif (_nested / "ui").is_dir():
    # Last-resort legacy fallback.
    sys.path.insert(0, str(_nested))
else:
    sys.path.insert(0, str(ROOT))

# ── Version ───────────────────────────────────────────────────────────────────
__version__ = "1.0.0"
APP_NAME    = "RAMDetect"

# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure root logger — console + rotating file in logs/."""
    logs_dir = ROOT / "logs"
    logs_dir.mkdir(exist_ok=True)
    log_file = logs_dir / "ramdetect.log"

    level   = logging.DEBUG if verbose else logging.INFO
    fmt     = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        from logging.handlers import RotatingFileHandler
        handlers.append(
            RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
        )
    except Exception:
        pass  # Non-fatal if log file can't be created

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, handlers=handlers)
    return logging.getLogger(APP_NAME)


# ── Dependency checks ─────────────────────────────────────────────────────────

def _check_dependencies(log: logging.Logger) -> bool:
    """Verify required packages are importable. Returns True if all present."""
    required = {
        "PyQt5":      "pip install PyQt5",
        "matplotlib": "pip install matplotlib",
        "pandas":     "pip install pandas",
        "sklearn":    "pip install scikit-learn",
        "yaml":       "pip install PyYAML",
    }
    missing = []
    for module, install_hint in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append((module, install_hint))

    optional = {
        "reportlab": "pip install reportlab  (enables PDF reports)",
    }
    for module, hint in optional.items():
        try:
            __import__(module)
        except ImportError:
            log.warning("Optional dependency missing — %s  ->  %s", module, hint)

    if missing:
        log.error("Missing required dependencies:")
        for mod, hint in missing:
            log.error("  x  %s   ->   %s", mod, hint)
        log.error("Run:  pip install -r requirements.txt")
        return False

    return True


# ── Admin / privilege check (Windows) ─────────────────────────────────────────

def _is_admin() -> bool:
    """Return True if the process has administrator privileges (Windows only)."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True  # Non-Windows — assume OK


# ── CLI handlers ──────────────────────────────────────────────────────────────

def _cmd_acquire(log: logging.Logger) -> int:
    """Trigger a live RAM acquisition via AcquisitionBridge (headless)."""
    if not _is_admin():
        log.error("Live acquisition requires Administrator privileges.")
        log.error("Re-run as Administrator or use --analyze with an existing dump.")
        return 1

    try:
        from ui.bridge.config_bridge import Config
        from ui.bridge.acquisition_bridge import AcquisitionBridge

        dumpit = Config.dumpit_path
        output = Config.output_dir

        if not Path(dumpit).exists():
            log.error("DumpIt not found at: %s", dumpit)
            log.error("Download DumpIt from https://www.comae.com/ and set the path in config.yaml")
            return 1

        log.info("Starting live RAM acquisition...")
        log.info("  DumpIt:  %s", dumpit)
        log.info("  Output:  %s", output)

        result = AcquisitionBridge.acquire_sync(dumpit, output)
        if result["success"]:
            log.info("Acquisition complete: %s  (%s)",
                     result["filename"], result.get("size_str", ""))
            log.info("Run:  python main.py --analyze \"%s\"", result["path"])
            return 0
        else:
            log.error("Acquisition failed: %s", result.get("error", "unknown error"))
            return 1

    except Exception as exc:
        log.exception("Unexpected error during acquisition: %s", exc)
        return 1


def _cmd_analyze(dump_path: str, log: logging.Logger) -> int:
    """Run a headless analysis on an existing memory dump."""
    path = Path(dump_path)
    if not path.exists():
        log.error("Dump file not found: %s", dump_path)
        return 1

    log.info("Analyzing dump: %s  (%s)", path.name,
             _human_size(path.stat().st_size))

    try:
        from ui.bridge.session import AppState
        from ui.bridge.analysis_bridge import AnalysisWorker
        from ui.bridge.ml_bridge import MLBridge
        from ui.bridge.report_bridge import ReportBridge

        sess = AppState.new_session()
        sess.dump_filename   = path.name
        sess.dump_size_bytes = path.stat().st_size
        sess.mode            = "file"
        sess.selected_modules = [
            "process", "thread", "dll", "handle", "pe_section", "injection"
        ]

        log.info("Running feature extraction...")
        try:
            # Run AnalysisWorker synchronously (no Qt event loop in CLI mode)
            worker = object.__new__(AnalysisWorker)
            worker._session   = sess
            worker._cancelled = False
            worker.run()
        except Exception as exc:
            log.error("Analysis worker error: %s", exc)
            return 1

        log.info("Running ML classification...")
        sess.ml_result = MLBridge.predict(sess.feature_vector or [])
        sess.findings   = MLBridge.derive_findings(sess)
        sess.status     = "complete"
        AppState.save_current()

        verdict    = sess.ml_result.get("verdict", "unknown").upper()
        confidence = sess.ml_result.get("confidence", 0)
        marker     = "!" if verdict == "SUSPICIOUS" else "+"

        print()
        print("=" * 60)
        print(f"  [{marker}] VERDICT:     {verdict}")
        print(f"      Confidence:  {confidence:.1f}%")
        print(f"      RF Score:    {sess.ml_result.get('rf_score', 0):.1f}%")
        print(f"      AE Score:    {sess.ml_result.get('ae_score', 0):.1f}%")
        print(f"      Findings:    {len(sess.findings)}")
        if sess.findings:
            for finding in sess.findings[:5]:
                sev = finding["severity"].upper()
                print(f"        [{sev:6}] {finding['category']}: {finding['description']}")
            if len(sess.findings) > 5:
                print(f"        ... and {len(sess.findings) - 5} more")
        print("=" * 60)
        print()

        log.info("Generating JSON report...")
        result = ReportBridge.generate(sess, "json")
        if result["success"]:
            log.info("Report saved: %s", result["path"])
        else:
            log.warning("Report generation failed: %s", result.get("error"))

        return 0

    except Exception as exc:
        log.exception("Unexpected error during analysis: %s", exc)
        return 1


def _cmd_train(dataset_path: str, log: logging.Logger) -> int:
    """Train ML models on a labelled dataset directory."""
    path = Path(dataset_path)
    if not path.exists():
        log.error("Dataset directory not found: %s", dataset_path)
        return 1

    log.info("Training ML models on dataset: %s", path)

    try:
        from ramdetect.ml.trainer import ModelTrainer  # type: ignore
        trainer = ModelTrainer(dataset_dir=str(path))
        trainer.train()
        log.info("Training complete. Models saved to: %s", ROOT / "models")
        return 0
    except ImportError:
        log.error("ML training module not yet available.")
        log.error("The 'ramdetect.ml' package is pending implementation.")
        log.error("See docs/architecture.md for the training pipeline specification.")
        return 1
    except Exception as exc:
        log.exception("Training failed: %s", exc)
        return 1


# ── GUI launch ────────────────────────────────────────────────────────────────

def _launch_gui(log: logging.Logger) -> int:
    """Start the PyQt5 GUI application."""
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QFont, QIcon
        from PyQt5.QtCore import Qt
    except ImportError:
        log.error("PyQt5 is not installed.  Run:  pip install PyQt5")
        return 1

    # Enable HiDPI scaling
    try:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    except AttributeError:
        pass  # Older Qt versions

    # Prevent noisy Qt font warnings in PyQt5 virtual environments on Windows.
    try:
        if os.name == "nt":
            win_fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
            if win_fonts.exists():
                os.environ.setdefault("QT_QPA_FONTDIR", str(win_fonts))
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("RAMDetect")
    app.setFont(QFont("Segoe UI", 10))

    def _app_icon_path() -> Path | None:
        """Resolve RAMDetect app/window icon in source and PyInstaller onedir mode."""
        base = Path(getattr(sys, "_MEIPASS", ROOT))
        candidates = [
            base / "assets" / "ramdetect.ico",
            ROOT / "assets" / "ramdetect.ico",
            base / "ramdetect" / "ui" / "resources" / "photo" / "ramdetect_black.png",
            ROOT / "ramdetect" / "ui" / "resources" / "photo" / "ramdetect_black.png",
            base / "ramdetect" / "ui" / "resources" / "photo" / "ramdetect_black.png",
            ROOT / "ramdetect" / "ui" / "resources" / "photo" / "ramdetect_black.png",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    icon_path = _app_icon_path()
    if icon_path is not None:
        app.setWindowIcon(QIcon(str(icon_path)))


    _apply_dark_palette(app)

    # Runtime connectivity detection for Offline Local Mode. If PostgreSQL is
    # unreachable, RAMDetect bypasses central login and opens the Analyst-level
    # local analysis workflow. This affects only activity/admin/repository access,
    # not the RF-AE ML verdict pipeline.
    runtime_info = {"mode": "online", "offline_mode": False, "reason": "connectivity check unavailable"}
    try:
        from ramdetect.case_management.connectivity import (
            apply_runtime_environment,
            detect_runtime_mode,
        )
        runtime_info = detect_runtime_mode(timeout_seconds=2)
        apply_runtime_environment(runtime_info)
        if runtime_info.get("offline_mode"):
            log.warning("Starting in Offline Local Mode: %s", runtime_info.get("reason"))
        else:
            log.info("Server connectivity OK; starting normal login mode.")
    except Exception as exc:
        # Fail open to the normal legacy path if the new connectivity helper is
        # unavailable. MainWindow/Activity Monitoring remains non-fatal.
        log.warning("Runtime connectivity check failed: %s", exc)

    # Activity-monitoring database initialization. Skip it in Offline Local Mode
    # so a copied client with no PTM network/server can still open immediately.
    if not runtime_info.get("offline_mode"):
        try:
            from ramdetect.case_management import initialise_database
            initialise_database()
        except Exception as exc:
            log.warning("Activity-monitoring database initialization failed: %s", exc)
    else:
        log.info("Offline Local Mode: skipped central activity database initialization.")

    try:
        from ui.main_window import MainWindow
    except Exception as exc:
        log.exception("Failed to load main window: %s", exc)
        _show_startup_error(app, str(exc))
        return 1

    log.info("Launching %s v%s", APP_NAME, __version__)
    window = MainWindow(runtime_info=runtime_info)
    window.show()

    return app.exec_()


def _apply_dark_palette(app) -> None:
    """Apply a dark QPalette so native dialogs and menus match the theme."""
    try:
        from PyQt5.QtGui import QPalette, QColor

        p = QPalette()
        C = QColor

        p.setColor(QPalette.Window,          C(15,  23,  42))
        p.setColor(QPalette.WindowText,      C(226, 232, 240))
        p.setColor(QPalette.Base,            C(30,  41,  59))
        p.setColor(QPalette.AlternateBase,   C(15,  23,  42))
        p.setColor(QPalette.ToolTipBase,     C(30,  41,  59))
        p.setColor(QPalette.ToolTipText,     C(226, 232, 240))
        p.setColor(QPalette.Text,            C(226, 232, 240))
        p.setColor(QPalette.Button,          C(51,  65,  85))
        p.setColor(QPalette.ButtonText,      C(226, 232, 240))
        p.setColor(QPalette.BrightText,      C(255, 255, 255))
        p.setColor(QPalette.Link,            C(6,  182, 212))
        p.setColor(QPalette.Highlight,       C(6,  182, 212))
        p.setColor(QPalette.HighlightedText, C(255, 255, 255))
        p.setColor(QPalette.Disabled, QPalette.Text,       C(100, 116, 139))
        p.setColor(QPalette.Disabled, QPalette.ButtonText, C(100, 116, 139))

        app.setPalette(p)
    except Exception:
        pass  # Non-fatal


def _show_startup_error(app, message: str) -> None:
    """Show a simple error dialog when the main window fails to load."""
    try:
        from PyQt5.QtWidgets import QMessageBox
        mb = QMessageBox()
        mb.setIcon(QMessageBox.Critical)
        mb.setWindowTitle(f"{APP_NAME} — Startup Error")
        mb.setText("Failed to start RAMDetect.")
        mb.setDetailedText(message)
        mb.exec_()
    except Exception:
        print(f"STARTUP ERROR: {message}", file=sys.stderr)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── Argument parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ramdetect",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(f"""\
            {APP_NAME} v{__version__} — ML-Powered RAM Forensics Analysis
            ─────────────────────────────────────────────────────────────
            Performs DumpIt-based RAM acquisition, RAMDetect artifact extraction,
            RF-AE feature-fusion classification, and forensic report generation
            for post-incident memory analysis.

            Volatility-assisted support is limited to two documented exceptions:
            (1) handle enumeration through the handle parser, and
            (2) DTB / OS profile metadata resolution through windows.info.Info.
            Neither exception affects the final RF-AE ML verdict.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              python main.py                          # Launch GUI
              python main.py --gui                    # Launch GUI (explicit)
              python main.py --analyze memory.dmp     # Headless analysis
              python main.py --acquire                # Live RAM dump (admin)
              python main.py --train --dataset ./data # Train ML models
        """),
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--gui",
        action="store_true",
        help="Launch the graphical interface (default when no mode specified)",
    )
    mode.add_argument(
        "--analyze",
        metavar="DUMP_FILE",
        help="Analyse an existing memory dump (headless, outputs JSON report)",
    )
    mode.add_argument(
        "--acquire",
        action="store_true",
        help="Capture a live RAM dump using DumpIt (requires Administrator)",
    )
    mode.add_argument(
        "--train",
        action="store_true",
        help="Train ML models on a labelled dataset (requires --dataset)",
    )

    parser.add_argument(
        "--dataset",
        metavar="DIR",
        default="./datasets",
        help="Path to training dataset directory (used with --train)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {__version__}",
    )

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = _build_parser()
    args   = parser.parse_args()

    log = _setup_logging(verbose=args.verbose)
    log.debug("Python %s  |  CWD: %s", sys.version.split()[0], os.getcwd())

    if not _check_dependencies(log):
        return 1

    if args.analyze:
        return _cmd_analyze(args.analyze, log)

    if args.acquire:
        return _cmd_acquire(log)

    if args.train:
        return _cmd_train(args.dataset, log)

    # Default: GUI (covers both explicit --gui and bare invocation)
    return _launch_gui(log)


if __name__ == "__main__":
    sys.exit(main())





"""RAMDetect UI theme foundation.

Phase 1 scope:
- Store the local Light/Dark UI preference with QSettings.
- Load one central QSS file at application level.
- Apply a matching Qt palette for native dialogs/menus.

This module is UI-only. It does not touch RAM acquisition, ML, database,
report generation, dump paths, repository sync, or offline-mode logic.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

THEME_DARK = "dark"
THEME_LIGHT = "light"
THEMES = (THEME_DARK, THEME_LIGHT)
_SETTINGS_ORG = "RAMDetect"
_SETTINGS_APP = "RAMDetect"
_SETTINGS_KEY = "ui/theme"
_STYLESHEET_CACHE: dict[tuple[str, float], str] = {}



def _normalise(theme: str | None) -> str:
    value = str(theme or "").strip().lower()
    return THEME_LIGHT if value == THEME_LIGHT else THEME_DARK


def _settings():
    from PyQt5.QtCore import QSettings
    return QSettings(_SETTINGS_ORG, _SETTINGS_APP)


def current_theme() -> str:
    """Return the saved theme. Dark is the safe default."""
    try:
        return _normalise(_settings().value(_SETTINGS_KEY, THEME_DARK))
    except Exception:
        return THEME_DARK


def save_theme(theme: str) -> str:
    """Persist and return the normalised theme name."""
    theme = _normalise(theme)
    try:
        _settings().setValue(_SETTINGS_KEY, theme)
        _settings().sync()
    except Exception:
        pass
    return theme


def resource_path(*parts: str) -> Path:
    """Return a path inside ramdetect/ui/resources."""
    return Path(__file__).resolve().parent / "resources" / Path(*parts)


def stylesheet_path(theme: str | None = None) -> Path:
    theme = _normalise(theme or current_theme())
    preferred = resource_path(f"styles_{theme}.qss")
    if preferred.is_file():
        return preferred
    return resource_path("styles.qss")


def load_stylesheet(theme: str | None = None) -> str:
    path = stylesheet_path(theme)
    try:
        stat = path.stat()
        key = (str(path), float(stat.st_mtime))
        cached = _STYLESHEET_CACHE.get(key)
        if cached is not None:
            return cached
        text = path.read_text(encoding="utf-8")
        _STYLESHEET_CACHE.clear()
        _STYLESHEET_CACHE[key] = text
        return text
    except Exception:
        return ""


def _apply_palette(app: Any, theme: str) -> None:
    """Apply a matching QPalette for native Qt controls/dialogs."""
    try:
        from PyQt5.QtGui import QPalette, QColor

        p = QPalette()
        C = QColor
        if theme == THEME_LIGHT:
            p.setColor(QPalette.Window,          C(240, 245, 255))
            p.setColor(QPalette.WindowText,      C(30, 58, 110))
            p.setColor(QPalette.Base,            C(255, 255, 255))
            p.setColor(QPalette.AlternateBase,   C(248, 251, 255))
            p.setColor(QPalette.ToolTipBase,     C(255, 255, 255))
            p.setColor(QPalette.ToolTipText,     C(30, 58, 110))
            p.setColor(QPalette.Text,            C(30, 58, 110))
            p.setColor(QPalette.Button,          C(255, 255, 255))
            p.setColor(QPalette.ButtonText,      C(30, 58, 110))
            p.setColor(QPalette.BrightText,      C(255, 255, 255))
            p.setColor(QPalette.Link,            C(26, 86, 219))
            p.setColor(QPalette.Highlight,       C(26, 86, 219))
            p.setColor(QPalette.HighlightedText, C(255, 255, 255))
            p.setColor(QPalette.Disabled, QPalette.Text,       C(148, 163, 184))
            p.setColor(QPalette.Disabled, QPalette.ButtonText, C(148, 163, 184))
        else:
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
        pass


def apply_theme(target: Any = None, theme: str | None = None, persist: bool = False) -> str:
    """Apply the selected theme to QApplication and return the active theme.

    Parameters
    ----------
    target:
        QApplication, QMainWindow, QWidget, or None. None means use the current
        QApplication instance.
    theme:
        "dark" or "light". None loads the saved value.
    persist:
        When True, write the selected theme to QSettings.
    """
    from PyQt5.QtWidgets import QApplication

    theme = _normalise(theme or current_theme())
    if persist:
        theme = save_theme(theme)

    app = target if isinstance(target, QApplication) else QApplication.instance()
    qss = load_stylesheet(theme)
    if app is not None:
        prev_theme = app.property("ramdetectTheme")
        # Avoid a full QApplication repolish when the selected theme did not
        # actually change. This protects against repeated switch signals.
        if prev_theme != theme or app.styleSheet() != qss:
            top_widgets = []
            try:
                top_widgets = list(app.topLevelWidgets())
                for widget in top_widgets:
                    widget.setUpdatesEnabled(False)
            except Exception:
                top_widgets = []
            try:
                app.setProperty("ramdetectTheme", theme)
                app.setStyleSheet(qss)
            finally:
                for widget in top_widgets:
                    try:
                        widget.setUpdatesEnabled(True)
                        widget.update()
                    except Exception:
                        pass
        else:
            app.setProperty("ramdetectTheme", theme)
        _apply_palette(app, theme)
    elif target is not None and hasattr(target, "setStyleSheet"):
        if target.property("ramdetectTheme") != theme or target.styleSheet() != qss:
            target.setProperty("ramdetectTheme", theme)
            target.setStyleSheet(qss)

    return theme

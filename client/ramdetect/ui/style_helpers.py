"""Small QSS helper functions for RAMDetect UI.

This module contains no colours or visual rules. It only assigns object names
and dynamic properties so ramdetect/ui/resources/styles.qss can own the visual
styling. Keeping this separate avoids adding a theme manager or theme toggle.
"""

from __future__ import annotations

from typing import Any


def refresh_style(widget: Any) -> None:
    """Re-polish a Qt widget after changing dynamic QSS properties."""
    if widget is None:
        return
    try:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()
    except Exception:
        pass


def _set_property(widget: Any, name: str, value: str) -> Any:
    """Set a dynamic QSS property only when it actually changes.

    Theme switching repolishes many widgets. Avoiding redundant unpolish/polish
    calls noticeably reduces the delay when moving between Light and Dark mode.
    """
    if widget is not None:
        try:
            if widget.property(name) == value:
                return widget
        except Exception:
            pass
        widget.setProperty(name, value)
        refresh_style(widget)
    return widget


def set_role(widget: Any, role: str) -> Any:
    return _set_property(widget, "role", role)


def set_variant(widget: Any, variant: str) -> Any:
    return _set_property(widget, "variant", variant)


def set_state(widget: Any, state: str) -> Any:
    return _set_property(widget, "state", state)


def set_tone(widget: Any, tone_or_color: str) -> Any:
    """Assign a semantic text tone.

    Existing pages often pass literal hex colours. The mapping keeps those old
    colours visually stable while moving the actual colour rules to styles.qss.
    """
    if widget is None:
        return widget
    value = (tone_or_color or "").strip().lower().replace(" ", "")
    mapping = {
        "#ffffff": "white",
        "white": "white",
        "#f8fafc": "white-soft",
        "#e2e8f0": "text",
        "#e0e6f0": "text",
        "#dbeafe": "blue-soft",
        "#cbd5e1": "text-muted-bright",
        "#a0adc4": "muted-bright",
        "#9fb0cc": "muted-bright",
        "#94a3b8": "muted",
        "#7a8cb0": "muted-dark",
        "#64748b": "muted-dark",
        "#475569": "disabled",
        "#334155": "slate",
        "#06b6d4": "cyan",
        "#22d3ee": "cyan-bright",
        "#38bdf8": "sky",
        "#2563eb": "blue",
        "#60a5fa": "blue-light",
        "#34d399": "green",
        "#22c55e": "green-strong",
        "#facc15": "yellow",
        "#f59e0b": "amber",
        "#f97316": "orange",
        "#fb923c": "orange-light",
        "#f87171": "red",
        "#ef4444": "red-strong",
        "#fecaca": "red-soft",
        "#a78bfa": "violet",
    }
    return _set_property(widget, "tone", mapping.get(value, value or "text"))


def set_severity(widget: Any, severity: str) -> Any:
    return _set_property(widget, "severity", (severity or "unknown").strip().lower())

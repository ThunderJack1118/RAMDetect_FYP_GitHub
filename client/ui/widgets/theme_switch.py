# Auto-generated RAMDetect compatibility shim.
# Real implementation is in: ramdetect.ui.widgets.theme_switch

from ramdetect.ui.widgets.theme_switch import *  # noqa: F401,F403
import ramdetect.ui.widgets.theme_switch as _target_module

_EXCLUDED = {
    "__name__", "__package__", "__loader__", "__spec__",
    "__file__", "__cached__", "__builtins__", "__path__"
}

for _name, _value in vars(_target_module).items():
    if _name not in _EXCLUDED:
        globals()[_name] = _value

__all__ = [name for name in globals() if not name.startswith("__")]

# Auto-generated RAMDetect compatibility shim.
# Real implementation is in: ramdetect.ui.theme

try:
    _shim_package_path = list(__path__)
except NameError:
    _shim_package_path = None

from ramdetect.ui.theme import *  # noqa: F401,F403
import ramdetect.ui.theme as _target_module

_EXCLUDED = {
    "__name__", "__package__", "__loader__", "__spec__",
    "__file__", "__cached__", "__builtins__", "__path__"
}

for _name, _value in vars(_target_module).items():
    if _name not in _EXCLUDED:
        globals()[_name] = _value

if _shim_package_path is not None:
    __path__ = _shim_package_path

__all__ = [name for name in globals() if not name.startswith("__")]

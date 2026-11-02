"""DNS topology package with seamless bridge to site-packages dnspython."""
from __future__ import annotations

from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

for _p in list(sys.path):
    if not _p:
        continue
    try:
        _cand = Path(_p).resolve()
    except OSError:
        continue
    if _cand == _ROOT:
        continue
    _ext_dns = _cand / "dns"
    if (_ext_dns / "__init__.py").is_file() and str(_ext_dns) not in __path__:
        __path__.append(str(_ext_dns))
        _init_code = (_ext_dns / "__init__.py").read_text(encoding="utf-8")
        exec(compile(_init_code, str(_ext_dns / "__init__.py"), "exec"), globals())
        break

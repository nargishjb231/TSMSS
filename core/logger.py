"""Dual-channel logging: human console + machine audit trail."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


def setup(log_dir: Path, level: str = "INFO") -> logging.Logger:
    global _CONFIGURED
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("tsmss")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if _CONFIGURED:
        return logger
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    fh = RotatingFileHandler(log_dir / "scanner.log", maxBytes=2_000_000,
                             backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(sh)
    logger.propagate = False
    _CONFIGURED = True
    return logger


def get(name: str = "tsmss") -> logging.Logger:
    return logging.getLogger(name)
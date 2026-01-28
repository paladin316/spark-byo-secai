from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

_LOGGER_NAME = "BYO-SecAI"
_initialized = False


def init_logging(data_dir: str | Path, filename: str = "byo_secai_debug.log") -> logging.Logger:
    """Initialize file + console logging once per process."""
    global _initialized
    logger = logging.getLogger(_LOGGER_NAME)

    if _initialized:
        return logger

    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on Streamlit reruns
    if logger.handlers:
        _initialized = True
        return logger

    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path = data_dir / filename

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info("Logging initialized (file=%s)", log_path)
    _initialized = True
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)

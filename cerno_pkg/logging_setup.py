"""Logging configuration and utilities with loguru fallback.

This module sets up file-based logging with configurable paths and levels
via config.yaml:
  - log_path: Path to log file (default: ~/.cerno/cerno.log)
  - debug_logging: Enable DEBUG level (default: False)

Prefers loguru if available, falls back to stdlib logging otherwise.
"""

import functools
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, TypeVar, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import CernoConfig


# ========== Logger backend selection ==========
# Initialize to prevent "possibly unbound" errors
_log: Any = None
_logging: Any = None
LOGURU_AVAILABLE: bool = False

try:
    from loguru import logger as _log
    LOGURU_AVAILABLE = True
except Exception:
    import logging as _logging


# ========== Helper functions ==========
def env_truthy(name: str, default: bool = False) -> bool:
    """Check if an environment variable is set to a truthy value.

    Args:
        name: Environment variable name to check
        default: Value to return if variable is not set

    Returns:
        True if variable is set to '1', 'true', 'yes', 'y', or 'on'
        (case-insensitive), otherwise the default value
    """
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def init_logger(config: Optional["CernoConfig"] = None) -> None:
    """Initialize the logging system from configuration.

    Args:
        config: Configuration object. If None, uses inline defaults.

    Configures file logging with:
    - Log path from config (default: ~/.cerno/cerno.log)
    - Log level from config (DEBUG if debug_logging=True, else INFO)
    - Rotation at 1 MB with 3 file retention (loguru only)

    Uses loguru if available, falls back to stdlib logging otherwise.
    Silently catches and ignores configuration errors.
    """
    global LOGURU_AVAILABLE

    # Get config values with defaults
    if config:
        log_path = config.log_path or str(Path.home() / ".cerno" / "cerno.log")
        debug = config.debug_logging
    else:
        log_path = str(Path.home() / ".cerno" / "cerno.log")
        debug = False

    level = "DEBUG" if debug else "INFO"

    try:
        if LOGURU_AVAILABLE:
            try:
                _log.remove()
            except Exception:
                pass
            _log.add(
                log_path,
                level=level,
                rotation="1 MB",
                retention=3,
                enqueue=False,
                backtrace=False,
                diagnose=False,
            )
            _log.info(
                "Logger initialized (loguru) at {} with level {}",
                log_path,
                level,
            )
        else:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            _logging.basicConfig(
                filename=log_path,
                level=_logging.DEBUG if debug else _logging.INFO,
                format="%(asctime)s %(levelname)s %(message)s",
            )
            _logging.info(
                "Logger initialized (stdlib) at %s with level %s",
                log_path,
                level,
            )
    except Exception:
        pass


# Note: Logger is NOT initialized on module import anymore
# Call init_logger(config) explicitly from main entry point


# ========== Logging convenience functions ==========
def log_info(msg: str) -> None:
    """Log an info-level message.

    Args:
        msg: The message to log
    """
    try:
        if LOGURU_AVAILABLE:
            _log.info(msg)
        else:
            _logging.info(msg)
    except Exception:
        pass


def log_debug(msg: str) -> None:
    """Log a debug-level message.

    Args:
        msg: The message to log
    """
    try:
        if LOGURU_AVAILABLE:
            _log.debug(msg)
        else:
            _logging.debug(msg)
    except Exception:
        pass


def log_error(msg: str) -> None:
    """Log an error-level message.

    Args:
        msg: The message to log
    """
    try:
        if LOGURU_AVAILABLE:
            _log.error(msg)
        else:
            _logging.error(msg)
    except Exception:
        pass


# ========== Global exception hook ==========
_orig_excepthook = sys.excepthook


def ex_hook(exc_type: type, exc: BaseException, tb: Any) -> Any:
    """Custom exception hook to log unhandled exceptions.

    Args:
        exc_type: The exception type
        exc: The exception instance
        tb: The traceback object

    Returns:
        Result of the original exception hook
    """
    try:
        if LOGURU_AVAILABLE:
            _log.opt(exception=(exc_type, exc, tb)).error(
                "Unhandled exception"
            )
        else:
            import traceback as _tb

            log_error(
                "Unhandled exception:\n"
                + "".join(_tb.format_exception(exc_type, exc, tb))
            )
    except Exception:
        pass
    return _orig_excepthook(exc_type, exc, tb)


sys.excepthook = ex_hook


# ========== Performance timing decorator ==========
F = TypeVar("F", bound=Callable[..., Any])


def log_timing(fn: F) -> F:
    """Decorator to log function execution time.

    Measures and logs the execution time of the wrapped function in
    milliseconds at DEBUG level.

    Args:
        fn: The function to wrap

    Returns:
        Wrapped function that logs execution time
    """

    @functools.wraps(fn)
    def _wrap(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            log_debug(f"{fn.__name__} took {elapsed_ms:.1f} ms")

    return _wrap  # type: ignore[return-value]


# ========== Public API ==========
def setup_logging(config: Optional["CernoConfig"] = None) -> None:
    """Public wrapper to initialize logging from config.

    Args:
        config: Configuration object. If None, uses inline defaults.
    """
    init_logger(config)
"""ANSI color code formatting and console output utilities.

This module provides ANSI color codes and helper functions for colorized
console output. Color configuration is managed via config.yaml.
"""

import os
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import CernoConfig

from .constants import SEVERITY_COLORS


# ========== Color configuration ==========
class C:
    """ANSI color code constants (initialized by initialize_colors).

    Provides escape codes for terminal colors and formatting.
    All codes evaluate to empty strings by default (no colors).
    Call initialize_colors(config) to enable colors based on configuration.
    """

    RESET: str = ""
    BOLD: str = ""
    BLUE: str = ""
    GREEN: str = ""
    YELLOW: str = ""
    RED: str = ""
    CYAN: str = ""
    MAGENTA: str = ""


def initialize_colors(config: Optional["CernoConfig"] = None) -> None:
    """Initialize color constants from configuration.

    Args:
        config: Configuration object. If None, loads config.
    """
    if config is None:
        from .config import load_config
        config = load_config()

    # Disable colors if configured
    if config.no_color or config.term_override == "dumb":
        # Colors already empty strings (defaults)
        return

    # Enable colors
    C.RESET = "\u001b[0m"
    C.BOLD = "\u001b[1m"
    C.BLUE = "\u001b[34m"
    C.GREEN = "\u001b[32m"
    C.YELLOW = "\u001b[33m"
    C.RED = "\u001b[31m"
    C.CYAN = "\u001b[36m"
    C.MAGENTA = "\u001b[35m"


def get_no_color(config: Optional["CernoConfig"] = None) -> bool:
    """Check if colors should be disabled.

    Args:
        config: Configuration object. If None, loads config.

    Returns:
        True if colors should be disabled
    """
    if config is None:
        from .config import load_config
        config = load_config()

    return config.no_color or config.term_override == "dumb"


# ========== Rich Console configuration ==========
_console_cache = None


def get_console(config: Optional["CernoConfig"] = None):
    """Get Rich Console instance configured with no_color setting.

    Returns a cached Console instance to ensure consistency across the application.
    The Console is initialized with no_color parameter based on configuration.

    Args:
        config: Configuration object. If None, loads config.

    Returns:
        Console instance with no_color parameter set appropriately
    """
    global _console_cache

    if _console_cache is None:
        from rich.console import Console

        if config is None:
            from .config import load_config
            config = load_config()

        _console_cache = Console(
            no_color=config.no_color or config.term_override == "dumb"
        )

    return _console_cache


def style_if_enabled(style_name: str, config: Optional["CernoConfig"] = None) -> str:
    """Return style name or empty string based on no_color configuration.

    Use this to conditionally apply Rich styles based on user configuration.

    Args:
        style_name: Rich style string (e.g., "bold cyan", "red", "yellow")
        config: Configuration object. If None, loads config.

    Returns:
        Style name if colors enabled, empty string if colors disabled

    Example:
        >>> text.stylize(style_if_enabled("green"))
        >>> table.add_column("Name", style=style_if_enabled("cyan"))
        >>> Panel(..., border_style=style_if_enabled("blue"))
    """
    if get_no_color(config):
        return ""
    return style_name


def header(msg: str) -> None:
    """Print a bold blue header message with newline prefix.

    Args:
        msg: The message to print as a header
    """
    print(f"{C.BOLD}{C.BLUE}\n{msg}{C.RESET}")


def ok(msg: str) -> None:
    """Print a success message in green with checkmark prefix.

    Args:
        msg: The success message to print
    """
    print(f"{C.GREEN}✓ {msg}{C.RESET}")


def warn(msg: str) -> None:
    """Print a warning message in yellow with warning icon prefix.

    Args:
        msg: The warning message to print
    """
    print(f"{C.YELLOW}⚠ {msg}{C.RESET}")


def err(msg: str) -> None:
    """Print an error message in red with error icon prefix.

    Args:
        msg: The error message to print
    """
    print(f"{C.RED}✗ {msg}{C.RESET}")


def info(msg: str) -> None:
    """Print an informational message without color.

    Args:
        msg: The informational message to print
    """
    print(msg)


def fmt_action(text: str) -> str:
    """Format text as an action with cyan color and >> prefix.

    Args:
        text: The action text to format

    Returns:
        Formatted action string with color codes
    """
    return f"{C.CYAN}>> {text}{C.RESET}"


def fmt_reviewed(text: str) -> str:
    """Format text as reviewed content in magenta with checkmark prefix.

    Args:
        text: The text to format as reviewed

    Returns:
        Formatted string with checkmark prefix and magenta color codes
    """
    return f"{C.MAGENTA}✓ {text}{C.RESET}"


def cyan_label(s: str) -> str:
    """Format a string with cyan color.

    Args:
        s: The string to colorize

    Returns:
        String wrapped in cyan ANSI codes
    """
    return f"{C.CYAN}{s}{C.RESET}"


def colorize_severity_label(label: str) -> str:
    """Colorize a severity label based on its level.

    Uses centralized SEVERITY_COLORS mapping from constants.py.
    Maps severity levels to colors:
    - Critical: Red
    - High: Yellow
    - Medium: Blue
    - Low: Green
    - Info: Cyan
    - Other: Magenta

    Args:
        label: The severity label to colorize

    Returns:
        Bold, colorized severity label string
    """
    normalized_label = label.strip().lower()

    # Look up color from centralized mapping
    for severity_key, (_, ansi_code) in SEVERITY_COLORS.items():
        if severity_key in normalized_label:
            color = "" if get_no_color() else ansi_code
            return f"{C.BOLD}{color}{label}{C.RESET}"

    # Default fallback
    _, default_ansi = SEVERITY_COLORS["default"]
    color = "" if get_no_color() else default_ansi
    return f"{C.BOLD}{color}{label}{C.RESET}"


def breadcrumb(*parts: str, max_width: int = 78) -> str:
    """Create a breadcrumb navigation string from parts.

    Args:
        *parts: Navigation parts (e.g., "Scan", "Severity", "Files")
        max_width: Maximum width before truncation (default: 78)

    Returns:
        Formatted breadcrumb string with '>' separators and cyan color

    Example:
        breadcrumb("MyS can", "4_Critical", "Files")
        → "MyScan > 4_Critical > Files"
    """
    if not parts:
        return ""

    separator = f"{C.CYAN} > {C.RESET}"
    # Build breadcrumb with colored parts
    colored_parts = [f"{C.CYAN}{part}{C.RESET}" for part in parts]
    breadcrumb_str = separator.join(colored_parts)

    # Calculate actual display width (without ANSI codes)
    display_str = " > ".join(parts)

    # Truncate if too long
    if len(display_str) > max_width:
        # Try truncating the last part
        available = max_width - len(" > ".join(parts[:-1])) - 3 - 5  # -3 for " > ", -5 for "..."
        if available > 10:
            last_part = parts[-1]
            truncated_last = last_part[:available] + "..."
            colored_parts[-1] = f"{C.CYAN}{truncated_last}{C.RESET}"
            breadcrumb_str = separator.join(colored_parts)
        else:
            # Too long even after truncation, just show first and last
            if len(parts) > 2:
                first = f"{C.CYAN}{parts[0][:20]}{C.RESET}"
                last = f"{C.CYAN}{parts[-1][:30]}...{C.RESET}"
                breadcrumb_str = f"{first}{separator}...{separator}{last}"

    return breadcrumb_str

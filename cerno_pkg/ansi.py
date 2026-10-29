"""ANSI color code formatting and console output utilities.

This module provides ANSI color codes and helper functions for colorized
console output. Color configuration is managed via config.yaml.
"""

import re
import shutil
from functools import lru_cache
from typing import Any, Optional, TYPE_CHECKING, Union

from rich.color import Color
from rich.console import Console
from rich.markup import escape
from rich.style import Style
from rich.theme import Theme

if TYPE_CHECKING:
    from .config import CernoConfig

from .constants import LIGHT_BG_COLOR_MAP, SEVERITY_COLORS

# ========== Color scheme (light/dark terminal background) ==========
_color_scheme: str = "light"
"""Active scheme for ANSI codes; set by initialize_colors()/get_console()."""


@lru_cache(maxsize=512)
def remap_style(style: str, scheme: str) -> str:
    """Rewrite named colors in a Rich style string for the given scheme.

    Under ``light`` (or any unknown scheme) each named color token, including a
    background after ``on``, is swapped via ``LIGHT_BG_COLOR_MAP``. Theme names
    (``prompt.choices``), hex/rgb colors and ``link`` URLs are left alone.
    ``dark`` returns the style unchanged.

    Args:
        style: Rich style definition (e.g. "bold yellow", "black on cyan")
        scheme: "light" or "dark"

    Returns:
        The style definition with colors remapped for the scheme
    """
    if scheme == "dark":
        return style
    tokens = style.split()
    out = []
    for i, token in enumerate(tokens):
        after_link = i > 0 and tokens[i - 1] == "link"
        out.append(token if after_link else LIGHT_BG_COLOR_MAP.get(token, token))
    return " ".join(out)


def _ansi_fg(color_name: str, scheme: str) -> str:
    """ANSI foreground escape for a Rich color name under the given scheme."""
    codes = Color.parse(remap_style(color_name, scheme)).get_ansi_codes()
    return f"\u001b[{';'.join(codes)}m"


class CernoConsole(Console):
    """Rich Console that remaps every string style for a color scheme.

    Rich resolves all string styles (markup tags, ``Text``/table/panel
    ``style=``) through ``get_style()``, so remapping there covers the whole UI
    without touching call sites. Rich's built-in theme (prompts, progress bars,
    markdown) is remapped the same way.
    """

    def __init__(self, *args: Any, scheme: str = "light", **kwargs: Any) -> None:
        from rich.default_styles import DEFAULT_STYLES

        self.color_scheme = scheme
        theme = Theme(
            {
                name: remap_style(str(style), scheme)
                for name, style in DEFAULT_STYLES.items()
                if str(style) != "none"
            }
        )
        super().__init__(*args, theme=theme, **kwargs)

    def get_style(
        self, name: Union[str, Style], *, default: Optional[Union[Style, str]] = None
    ) -> Style:
        if isinstance(name, str):
            name = remap_style(name, self.color_scheme)
        return super().get_style(name, default=default)


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

    global _color_scheme
    _color_scheme = config.color_scheme

    # Disable colors if configured
    if config.no_color or config.term_override == "dumb":
        # Colors already empty strings (defaults)
        return

    # Enable colors (derived from Rich color names so both schemes share one map)
    scheme = config.color_scheme
    C.RESET = "\u001b[0m"
    C.BOLD = "\u001b[1m"
    C.BLUE = _ansi_fg("blue", scheme)
    C.GREEN = _ansi_fg("green", scheme)
    C.YELLOW = _ansi_fg("yellow", scheme)
    C.RED = _ansi_fg("red", scheme)
    C.CYAN = _ansi_fg("cyan", scheme)
    C.MAGENTA = _ansi_fg("magenta", scheme)


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


def get_terminal_width(fallback: int = 80) -> int:
    """Get current terminal width with fallback.

    Detects the terminal width using shutil.get_terminal_size().
    Returns the fallback value if detection fails.

    Args:
        fallback: Default width if detection fails (default: 80)

    Returns:
        Terminal width in characters (minimum fallback value)

    Example:
        >>> width = get_terminal_width()
        >>> if width < 100:
        ...     # Use narrow layout
        >>> else:
        ...     # Use wide layout
    """
    try:
        width = shutil.get_terminal_size((fallback, 24)).columns
        return max(fallback, width)
    except Exception:
        return fallback


# ========== Rich Console configuration ==========
_console_cache = None


def get_console(config: Optional["CernoConfig"] = None):
    """Get the shared CernoConsole configured from no_color/term_override/color_scheme.

    Returns a cached CernoConsole so every module shares one instance. It honours
    no_color (or term_override == "dumb"), remaps named colors for the active
    color_scheme (light by default), and is installed as Rich's global console so
    Prompt/Progress output uses the same palette.

    Args:
        config: Configuration object. If None, loads config.

    Returns:
        The cached CernoConsole instance
    """
    global _console_cache, _color_scheme

    if _console_cache is None:
        import rich

        if config is None:
            from .config import load_config

            config = load_config()

        _color_scheme = config.color_scheme
        _console_cache = CernoConsole(
            scheme=config.color_scheme,
            no_color=config.no_color or config.term_override == "dumb",
        )
        # Rich's Prompt/Confirm/Progress fall back to rich's global console
        # when no console= is passed; point it at ours so they share the scheme.
        rich._console = _console_cache

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


# ========== Untrusted-text sanitization ==========
# Scan-derived text (plugin names, hostnames, scan names, NetExec values, tool
# output) is attacker-influenced: it arrives from third-party .nessus files and
# CLI arguments. Interpolating it raw into Rich markup lets a name containing
# square brackets crash rendering, silently swallow text, restyle output or
# inject an OSC-8 hyperlink; printing it raw lets escape sequences retitle the
# operator's terminal or move the cursor.

#: C0 controls plus DEL, keeping tab and newline (both legitimate in output).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

#: Whole escape sequences: OSC (ESC ] ... BEL|ST), CSI (ESC [ ... final byte),
#: and the two-character ESC forms.
_ESC_SEQ_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)" r"|\x1b\[[0-9;?]*[ -/]*[@-~]" r"|\x1b[@-_]"
)

#: SGR (color/style) sequences only - these are safe and often intentional.
_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")


def _scrub(chunk: str) -> str:
    """Drop every escape sequence and control character from a fragment."""
    return _CONTROL_RE.sub("", _ESC_SEQ_RE.sub("", chunk))


def strip_unsafe_escapes(text: str) -> str:
    """Remove dangerous terminal escapes, preserving SGR color sequences.

    Used by the message helpers below, which write raw ANSI via ``print()``.
    SGR is kept so deliberate coloring still works (captured nmap/NetExec
    output is colored, and ``tools.py`` passes ``C.BOLD`` into ``info()``);
    OSC (window title, OSC-8 hyperlinks) and cursor-movement sequences are
    removed.

    The trade-off is deliberate: an attacker-influenced string reaching these
    helpers can still change *colors*, which is cosmetic, but can no longer
    retitle the terminal, move the cursor or plant a hyperlink. Note that
    ``.nessus`` data cannot carry an ESC byte at all (it is invalid XML), so
    the residual surface is tool output, NetExec values and file names. Values
    interpolated into Rich *markup* get no such carve-out -- see
    :func:`safe_text`.

    Args:
        text: Text that may contain terminal escape sequences

    Returns:
        The text with only SGR escapes left intact
    """
    parts: list[str] = []
    pos = 0
    for match in _SGR_RE.finditer(text):
        parts.append(_scrub(text[pos : match.start()]))
        parts.append(match.group(0))  # keep intentional color verbatim
        pos = match.end()
    parts.append(_scrub(text[pos:]))
    return "".join(parts)


def safe_text(value: object) -> str:
    """Neutralize untrusted text for interpolation into a Rich markup string.

    Strips every terminal escape and control character, then escapes Rich
    markup so brackets render literally. Use this wherever scan-derived text is
    embedded in an f-string containing markup tags. Where a value carries a
    single style, prefer ``rich.text.Text(value, style=...)`` instead: ``Text``
    never parses markup, so it is immune by construction rather than by being
    remembered.

    Args:
        value: Any value; coerced with ``str()``

    Returns:
        Markup-safe, control-character-free text
    """
    return escape(_scrub(str(value)))


# ========== Message output ==========
def header(msg: str) -> None:
    """Print a bold blue header message with newline prefix.

    Args:
        msg: The message to print as a header
    """
    print(f"{C.BOLD}{C.BLUE}\n{strip_unsafe_escapes(msg)}{C.RESET}")


def ok(msg: str) -> None:
    """Print a success message in green with checkmark prefix.

    Args:
        msg: The success message to print
    """
    print(f"{C.GREEN}✓ {strip_unsafe_escapes(msg)}{C.RESET}")


def warn(msg: str) -> None:
    """Print a warning message in yellow with warning icon prefix.

    Args:
        msg: The warning message to print
    """
    print(f"{C.YELLOW}⚠ {strip_unsafe_escapes(msg)}{C.RESET}")


def err(msg: str) -> None:
    """Print an error message in red with error icon prefix.

    Args:
        msg: The error message to print
    """
    print(f"{C.RED}✗ {strip_unsafe_escapes(msg)}{C.RESET}")


def info(msg: str) -> None:
    """Print an informational message without color.

    Args:
        msg: The informational message to print
    """
    print(strip_unsafe_escapes(msg))


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
    Maps severity levels to colors (named for the dark scheme; the default
    light scheme swaps each for a darker variant via LIGHT_BG_COLOR_MAP):
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
    for severity_key, (rich_color, _) in SEVERITY_COLORS.items():
        if severity_key in normalized_label:
            color = "" if get_no_color() else _ansi_fg(rich_color, _color_scheme)
            return f"{C.BOLD}{color}{label}{C.RESET}"

    # Default fallback
    default_rich, _ = SEVERITY_COLORS["default"]
    color = "" if get_no_color() else _ansi_fg(default_rich, _color_scheme)
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
        available = (
            max_width - len(" > ".join(parts[:-1])) - 3 - 5
        )  # -3 for " > ", -5 for "..."
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

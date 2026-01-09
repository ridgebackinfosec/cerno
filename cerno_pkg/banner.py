"""
Promotional banner for cerno CLI tool.
"""

from rich.panel import Panel
from rich.text import Text

from cerno_pkg._version import __version__
from cerno_pkg.ansi import get_console, style_if_enabled


def display_banner() -> None:
    """
    Display the Ridgeback InfoSec promotional banner.

    This banner promotes Ridgeback InfoSec, LLC and their Offensive Tooling classes.
    Can be suppressed with the -q/--quiet flag.
    """
    console = get_console()

    # Create banner text with colors that work on both light and dark backgrounds
    banner_text = Text()
    banner_text.append(f"Cerno v{__version__}", style=style_if_enabled("bold cyan"))
    banner_text.append(" - by ")
    banner_text.append("Ridgeback InfoSec, LLC", style=style_if_enabled("bold magenta"))
    banner_text.append("\n\n")
    banner_text.append("Check out our Offensive Tooling training!\n", style=style_if_enabled("bold"))
    banner_text.append("   -> ")
    banner_text.append("https://ridgebackinfosec.com/training", style=style_if_enabled("bold blue underline"))

    # Display as a panel
    panel = Panel(
        banner_text,
        border_style=style_if_enabled("blue"),
        padding=(1, 2),
        expand=False
    )

    console.print(panel)
    console.print()  # Add spacing after banner

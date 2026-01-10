"""
Network security tooling automation and command generation.

This module provides utilities for building and executing commands for
various security tools including nmap, netexec, and metasploit.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import CernoConfig
    from .models import Plugin, Finding

import pyperclip
from rich.prompt import Prompt
from rich.text import Text

from .ansi import header, info, ok, warn
from .constants import (
    NETEXEC_PROTOCOLS,
    NSE_PROFILES,
)
from .tool_context import ToolContext, CommandResult

# Optional dependencies for Metasploit search
try:
    import requests  # type: ignore[reportUnusedImport]
    from bs4 import BeautifulSoup, Tag  # type: ignore[reportUnusedImport]
    METASPLOIT_DEPS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore
    BeautifulSoup = None  # type: ignore
    Tag = None  # type: ignore
    METASPLOIT_DEPS_AVAILABLE = False

from .ansi import get_console
_console = get_console()


def print_action_menu(actions: list[tuple[str, str]]) -> None:
    """Print action menu with Rich Text formatting.

    Args:
        actions: List of (key, description) tuples.
                Examples: [("V", "View file"), ("B", "Back")]
    """
    from .ansi import style_if_enabled
    action_text = Text()
    for i, (key, desc) in enumerate(actions):
        if i > 0:
            action_text.append(" / ", style=None)
        action_text.append(f"[{key}] ", style=style_if_enabled("cyan"))
        action_text.append(desc, style=None)

    _console.print("[cyan]>>[/cyan] ", end="")
    _console.print(action_text)


# Constants
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36"
)
HTTP_HEADERS = {"User-Agent": USER_AGENT}
PARENTHESIS_PATTERN = re.compile(r"\(([^)]+)\)")
MSF_PATTERN = re.compile(r"Metasploit[:\-\s]*\(?([^)]+)\)?", re.IGNORECASE)


# ========== NSE Profile Selection ==========

def choose_nse_profile(config: Optional["CernoConfig"] = None) -> tuple[list[str], bool]:
    """
    Prompt user to select an NSE (Nmap Scripting Engine) profile.

    Args:
        config: Optional configuration object. If None, loads config.

    Returns:
        Tuple of (script_list, needs_udp) where script_list contains
        the selected NSE scripts and needs_udp indicates if UDP scanning
        is required.
    """
    # Load config if not provided
    if config is None:
        from .config import load_config
        config = load_config()

    header("NSE Profiles")
    for index, (name, description, scripts, _) in enumerate(NSE_PROFILES, 1):
        # Highlight config default if it matches
        if config.nmap_default_profile and name.lower() == config.nmap_default_profile.lower():
            print(f"[{index}] {name} - {description} (default)")
        else:
            print(f"[{index}] {name} - {description}")
        info(f"    Scripts: {', '.join(scripts)}")
    print_action_menu([("N", "None (no NSE profile)"), ("B", "Back")])

    # Show default hint if configured
    if config.nmap_default_profile:
        print(f"(Press Enter for '{config.nmap_default_profile}')")

    while True:
        try:
            answer = Prompt.ask("Choose").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return [], False

        if answer in ("b", "back", "q"):
            return [], False

        # Handle default selection (Enter key) if config has default
        if answer == "" and config.nmap_default_profile:
            # Find matching profile by name
            for index, (name, description, scripts, needs_udp) in enumerate(NSE_PROFILES):
                if name.lower() == config.nmap_default_profile.lower():
                    ok(
                        f"Selected profile: {name} — "
                        f"including: {', '.join(scripts)}"
                    )
                    return scripts[:], needs_udp
            # If no match found, fall through to "none"

        if answer in ("n", "none", ""):
            return [], False

        if answer.isdigit():
            profile_index = int(answer)
            if 1 <= profile_index <= len(NSE_PROFILES):
                name, description, scripts, needs_udp = NSE_PROFILES[profile_index - 1]
                ok(
                    f"Selected profile: {name} — "
                    f"including: {', '.join(scripts)}"
                )
                return scripts[:], needs_udp

        warn("Invalid choice.")


# ========== Command Builders ==========

def build_nmap_cmd(
    udp: bool,
    nse_option: Optional[str],
    ips_file: Path,
    ports_str: str,
    use_sudo: bool,
    output_base: Path,
) -> list[str]:
    """
    Build an nmap command with the specified options.
    
    Args:
        udp: Whether to perform UDP scanning
        nse_option: NSE script option string (e.g., "--script=...")
        ips_file: Path to file containing IP addresses
        ports_str: Port specification string
        use_sudo: Whether to run with sudo
        output_base: Base path for output files
        
    Returns:
        Command as list of strings ready for subprocess execution
    """
    cmd = []
    
    if use_sudo:
        cmd.append("sudo")
    
    cmd.extend(["nmap", "-A"])
    
    if nse_option:
        cmd.append(nse_option)
    
    cmd.extend(["-iL", str(ips_file)])
    
    if udp:
        cmd.append("-sU")
    
    if ports_str:
        cmd.extend(["-p", ports_str])
    
    cmd.extend(["-oA", str(output_base)])
    
    return cmd


def build_netexec_cmd(
    exec_bin: str,
    protocol: str,
    ips_file: Path,
    output_base: Path,
) -> tuple[list[str], str, Optional[str]]:
    """
    Build a netexec command for the specified protocol.
    
    Args:
        exec_bin: Path to netexec binary
        protocol: Protocol to scan (e.g., 'smb', 'ssh')
        ips_file: Path to file containing IP addresses
        output_base: Base path for output files
        
    Returns:
        Tuple of (command, log_path, relay_path) where relay_path
        is only set for SMB protocol
    """
    log_path = f"{str(output_base)}.nxc.{protocol}.log"
    relay_path = None
    
    if protocol == "smb":
        relay_path = f"{str(output_base)}.SMB_Signing_not_required_targets.txt"
        cmd = [
            exec_bin,
            "smb",
            str(ips_file),
            "--gen-relay-list",
            relay_path,
            "--shares",
            "--log",
            log_path,
        ]
    else:
        cmd = [exec_bin, protocol, str(ips_file), "--log", log_path]
    
    return cmd, log_path, relay_path


# ========== Tool Selection ==========

def choose_tool(config: Optional["CernoConfig"] = None) -> Optional[str]:
    """
    Prompt user to select a security tool.

    This function is now data-driven from the tool registry. Tools are
    automatically displayed based on their registration in TOOL_REGISTRY.

    Args:
        config: Optional configuration object. If None, loads config.

    Returns:
        Tool id ('nmap', 'netexec', 'metasploit', 'custom') or
        None if user cancels
    """
    from .tool_registry import get_available_tools, get_tool_by_menu_index

    # Load config if not provided
    if config is None:
        from .config import load_config
        config = load_config()

    # Get all registered tools sorted by menu_order
    available_tools = get_available_tools(check_requirements=False)

    if not available_tools:
        warn("No tools available in registry.")
        return None

    # Display menu header
    header("Choose a tool")

    # Display tools dynamically from registry
    for index, tool in enumerate(available_tools, start=1):
        # Format: [1] nmap or [2] netexec — multi-protocol
        if tool.description and tool.description != tool.name:
            print(f"[{index}] {tool.name} — {tool.description}")
        else:
            print(f"[{index}] {tool.name}")

    print_action_menu([("B", "Back")])

    # Use config default if available and valid, otherwise first tool
    default_tool = None
    if config.default_tool:
        # Find tool by id in available_tools
        for tool in available_tools:
            if tool.id == config.default_tool:
                default_tool = tool
                break

    # Fall back to first tool if no valid config default
    if not default_tool and available_tools:
        default_tool = available_tools[0]

    if default_tool:
        print(f"(Press Enter for '{default_tool.name}')")

    while True:
        try:
            answer = Prompt.ask("Choose", default="" if default_tool else None)
            answer = (answer or "").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return None

        # Handle default (Enter key)
        if answer == "" and default_tool:
            return default_tool.id

        # Handle back/cancel
        if answer in ("b", "back", "q"):
            return None

        # Handle numeric selection
        if answer.isdigit():
            choice_index = int(answer)
            selected_tool = get_tool_by_menu_index(choice_index, available_only=False)
            if selected_tool:
                return selected_tool.id

        warn("Invalid choice.")


def choose_netexec_protocol(config: Optional["CernoConfig"] = None) -> Optional[str]:
    """
    Prompt user to select a netexec protocol.

    Args:
        config: Optional configuration object. If None, loads config.

    Returns:
        Protocol name or None if user cancels. Defaults to config.default_netexec_protocol
        or 'smb' if user presses Enter.
    """
    # Load config if not provided
    if config is None:
        from .config import load_config
        config = load_config()

    # Use config default or fall back to 'smb'
    default_proto = config.default_netexec_protocol or "smb"

    header("NetExec: choose protocol")
    for index, protocol in enumerate(NETEXEC_PROTOCOLS, 1):
        print(f"[{index}] {protocol}")
    print_action_menu([("B", "Back")])
    print(f"(Press Enter for '{default_proto}')")

    while True:
        try:
            answer = Prompt.ask("Choose protocol", default=default_proto).strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return None

        if answer == "":
            return default_proto
        
        if answer in ("b", "back", "q"):
            return None
        
        if answer.isdigit():
            protocol_index = int(answer)
            if 1 <= protocol_index <= len(NETEXEC_PROTOCOLS):
                return NETEXEC_PROTOCOLS[protocol_index - 1]
        
        if answer in NETEXEC_PROTOCOLS:
            return answer
        
        warn("Invalid choice.")


# ========== Custom Command Handling ==========

def custom_command_help(placeholder_mapping: dict[str, str]) -> None:
    """
    Display help information for custom command placeholders.
    
    Args:
        placeholder_mapping: Dictionary mapping placeholder names to
            their expanded values
    """
    header("Custom command")
    info(
        "You can type any shell command. "
        "The placeholders below will be expanded:"
    )
    for placeholder, value in placeholder_mapping.items():
        info(f"  {placeholder:14s} -> {value}")
    print()
    info("Examples:")
    info("  httpx -l {TCP_IPS} -silent -o {OABASE}.urls.txt")
    info("  nuclei -l {OABASE}.urls.txt -o {OABASE}.nuclei.txt")
    info("  cat {TCP_IPS} | xargs -I{} sh -c 'echo {}; nmap -Pn -p {PORTS} {}'")


def render_placeholders(template: str, mapping: dict[str, str]) -> str:
    """
    Replace placeholders in template string with their values.
    
    Args:
        template: String containing placeholders in {PLACEHOLDER} format
        mapping: Dictionary mapping placeholder names to values
        
    Returns:
        Template string with placeholders replaced
    """
    result = template
    for placeholder, value in mapping.items():
        result = result.replace(placeholder, str(value))
    return result


# ========== Command Review ==========

def command_review_menu(cmd_list_or_str: list[str] | str) -> str:
    """
    Display command review menu and get user action.
    
    Args:
        cmd_list_or_str: Command as list of strings or single string
        
    Returns:
        User action: 'run', 'copy', or 'cancel'
    """
    header("Command Review")
    
    if isinstance(cmd_list_or_str, str):
        cmd_str = cmd_list_or_str
    else:
        cmd_str = " ".join(cmd_list_or_str)
    
    print(cmd_str)
    print()
    print_action_menu([
        ("1", "Run now"),
        ("2", "Copy command to clipboard (don't run)"),
        ("B", "Back")
    ])

    while True:
        try:
            choice = Prompt.ask("Choose").strip()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return "cancel"

        if choice in ("1", "r", "run"):
            return "run"

        if choice in ("2", "c", "copy"):
            return "copy"

        if choice in ("b", "back", "q"):
            return "cancel"

        warn("Enter 1, 2, or [B]ack.")


# ========== Clipboard Operations ==========

def copy_to_clipboard(text: str) -> tuple[bool, str]:
    """
    Copy text to clipboard using available methods.
    
    Tries pyperclip first, then falls back to OS-specific tools
    (pbcopy, clip, xclip, wl-copy, xsel).
    
    Args:
        text: Text to copy to clipboard
        
    Returns:
        Tuple of (success, message) indicating whether copy succeeded
        and describing the method used or error encountered
    """
    # Try pyperclip first
    try:
        pyperclip.copy(text)
        return True, "Copied using pyperclip."
    except Exception:
        pass
    
    # Fall back to OS-specific tools
    encoded_text = text.encode("utf-8")
    clipboard_tools = []
    
    # macOS
    if sys.platform.startswith("darwin") and shutil.which("pbcopy"):
        clipboard_tools.append(("pbcopy", ["pbcopy"]))
    
    # Windows
    if os.name == "nt" and shutil.which("clip"):
        clipboard_tools.append(("clip", ["clip"]))
    
    # Linux/Unix
    for tool, args in [
        ("xclip", ["xclip", "-selection", "clipboard"]),
        ("wl-copy", ["wl-copy"]),
        ("xsel", ["xsel", "--clipboard", "--input"]),
    ]:
        if shutil.which(tool):
            clipboard_tools.append((tool, args))
    
    # Try each available tool
    for tool_name, tool_args in clipboard_tools:
        try:
            subprocess.run(
                tool_args,
                input=encoded_text,
                check=True,
                capture_output=True,
            )
            return True, f"Copied using {tool_name}."
        except subprocess.CalledProcessError as exc:
            return False, f"Clipboard tool failed (exit {exc.returncode})."
        except Exception as exc:
            return False, f"Clipboard error: {exc}"
    
    # Provide platform-specific installation guidance
    if sys.platform.startswith("linux"):
        return False, (
            "No clipboard tool found. Install one of: xclip, wl-copy, or xsel.\n"
            "    Debian/Ubuntu: sudo apt install xclip\n"
            "    Fedora: sudo dnf install xclip\n"
            "    Arch: sudo pacman -S xclip"
        )
    elif sys.platform.startswith("darwin"):
        return False, "Clipboard not available. pbcopy should be pre-installed on macOS."
    elif os.name == "nt":
        return False, "Clipboard not available. clip should be pre-installed on Windows."
    else:
        return False, "No suitable clipboard method found for your platform."


# ========== Metasploit Helpers ==========

def _build_msfconsole_commands(term: str) -> list[str]:
    """
    Build msfconsole one-liner command for a search term.

    Args:
        term: Metasploit module search term

    Returns:
        List containing single msfconsole command string
    """
    # Use appropriate quoting based on term content
    if "'" in term:
        cmd = f'msfconsole -q -x "search {term}; exit"'
    else:
        cmd = f"msfconsole -q -x 'search {term}; exit'"

    return [cmd]


def show_msf_available(plugin_url: str) -> None:
    """
    Display notice that Metasploit module is available.

    Non-blocking informational message shown when file ends with '-MSF.txt'.

    Args:
        plugin_url: URL of the plugin page (not used but kept for API
            compatibility)
    """
    header("Metasploit module available!")
    info(
        'Select "metasploit" in the tool menu to search for '
        "available modules.\n"
    )


# ===================================================================
# Tool Workflow Orchestration (moved from cerno.py)
# ===================================================================


def build_nmap_workflow(ctx: "ToolContext") -> Optional["CommandResult"]:
    """
    Build nmap command through interactive prompts.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if interrupted
    """
    from .tool_context import CommandResult
    from rich.prompt import Confirm, Prompt
    from .ansi import warn, info, C
    from .ops import require_cmd

    try:
        udp_ports = Confirm.ask(
            "\nDo you want to perform UDP scanning instead of TCP?", default=False
        )
    except KeyboardInterrupt:
        return None

    try:
        from .config import load_config
        config = load_config()
        nse_scripts, needs_udp = choose_nse_profile(config)
    except KeyboardInterrupt:
        return None

    try:
        extra = Prompt.ask(
            "Enter additional NSE scripts (comma-separated, no spaces, or Enter to skip)",
            default=""
        ).strip()
    except KeyboardInterrupt:
        return None

    if extra:
        for script in extra.split(","):
            script = script.strip()
            if script and script not in nse_scripts:
                nse_scripts.append(script)

    extras_imply_udp = any(
        script.lower().startswith("snmp") or script.lower() == "ipmi-version"
        for script in nse_scripts
    )

    if needs_udp or extras_imply_udp:
        if not udp_ports:
            warn("SNMP/IPMI selected — switching to UDP scan.")
        udp_ports = True

    if nse_scripts:
        info(f"{C.BOLD}NSE scripts to run:{C.RESET} {','.join(nse_scripts)}")

    nse_option = f"--script={','.join(nse_scripts)}" if nse_scripts else ""

    ips_file = ctx.udp_ips if udp_ports else ctx.tcp_ips
    require_cmd("nmap")
    cmd = build_nmap_cmd(udp_ports, nse_option, ips_file, ctx.ports_str, ctx.use_sudo, ctx.oabase)

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Results base:  {ctx.oabase}  (nmap -oA)",
    )


def build_netexec_workflow(ctx: "ToolContext") -> Optional["CommandResult"]:
    """
    Build netexec command through interactive prompts.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if interrupted
    """
    from .tool_context import CommandResult
    from .ansi import warn, info
    from .ops import resolve_cmd
    from .config import load_config

    config = load_config()
    protocol = choose_netexec_protocol(config)
    if not protocol:
        return None

    exec_bin = resolve_cmd(["nxc", "netexec"])
    if not exec_bin:
        warn("Neither 'nxc' nor 'netexec' was found in PATH.")
        info("Skipping run; returning to tool menu.")
        return None

    cmd, nxc_log, relay_path = build_netexec_cmd(exec_bin, protocol, ctx.tcp_ips, ctx.oabase)

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"NetExec log:   {nxc_log}",
        relay_path=Path(relay_path) if relay_path else None,
    )


def build_custom_workflow(ctx: "ToolContext") -> Optional["CommandResult"]:
    """
    Build custom command from user template with placeholder substitution.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if cancelled
    """
    from .tool_context import CommandResult
    from rich.prompt import Prompt
    from .ansi import warn

    mapping = {
        "{TCP_IPS}": ctx.tcp_ips,
        "{UDP_IPS}": ctx.udp_ips,
        "{TCP_HOST_PORTS}": ctx.tcp_sockets,
        "{PORTS}": ctx.ports_str or "",
        "{WORKDIR}": ctx.workdir,
        "{RESULTS_DIR}": ctx.results_dir,
        "{OABASE}": ctx.oabase,
    }
    custom_command_help(mapping)

    try:
        template = Prompt.ask(
            "\nEnter your command (placeholders allowed)"
        ).strip()
    except KeyboardInterrupt:
        return None

    if not template:
        warn("No command entered.")
        return None

    rendered = render_placeholders(template, mapping)

    return CommandResult(
        command=rendered,
        display_command=rendered,
        artifact_note=f"OABASE path:   {ctx.oabase}",
    )


def run_tool_workflow(
    plugin: "Plugin",
    finding: "Finding",
    scan_dir: Path,
    sev_dir: Path,
    hosts: list[str],
    ports_str: str,
    args,  # types.SimpleNamespace
    use_sudo: bool,
) -> bool:
    """
    Execute tool selection and execution workflow.

    NOTE: This function now accepts Plugin/Finding objects directly instead
    of extracting plugin_id from filenames. This eliminates redundant parsing
    and aligns with the database-first architecture.

    Args:
        plugin: Plugin database object with metadata
        finding: Finding database object
        scan_dir: Scan directory
        sev_dir: Severity directory
        hosts: List of target hosts
        ports_str: Comma-separated ports
        args: Command-line arguments namespace
        use_sudo: Whether sudo is available

    Returns:
        True if any tool was executed, False otherwise
    """
    import random
    import tempfile
    import subprocess
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.prompt import Confirm, IntPrompt, Prompt
    from .ansi import warn, ok, err, info, header, get_console
    from .constants import SAMPLE_THRESHOLD, get_results_root
    from .fs import build_results_paths, pretty_severity_label, write_work_files
    from .ops import run_command_with_progress, log_tool_execution, log_artifacts_for_nmap
    from .tool_registry import get_tool
    from .tool_context import ToolContext

    _console_global = get_console()

    sample_hosts = hosts

    if len(hosts) > SAMPLE_THRESHOLD:
        try:
            do_sample = Confirm.ask(
                f"There are {len(hosts)} hosts. Sample a subset?", default=False
            )
        except KeyboardInterrupt:
            return False

        if do_sample:
            while True:
                try:
                    sample_count = IntPrompt.ask(
                        "How many hosts to sample?",
                        default=min(10, len(hosts))
                    )
                except KeyboardInterrupt:
                    warn("\nInterrupted — not sampling.")
                    break

                if sample_count <= 0:
                    warn("Enter a positive integer.")
                    continue

                count = min(sample_count, len(hosts))
                sample_hosts = random.sample(hosts, count)
                ok(f"Sampling {count} host(s).")
                break

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        progress.add_task("Preparing workspace...", start=True)
        workdir = Path(tempfile.mkdtemp(prefix="nph_work_"))
        tcp_ips, udp_ips, tcp_sockets = write_work_files(
            workdir, sample_hosts, ports_str, udp=True
        )

    # Create synthetic filename for output directory structure
    # Format: {plugin_id}_{plugin_name}
    synthetic_filename = f"{plugin.plugin_id}_{plugin.plugin_name.replace(' ', '_').replace('/', '_')}"

    out_dir_static = (
        get_results_root()
        / scan_dir.name
        / pretty_severity_label(sev_dir.name)
        / synthetic_filename
    )
    out_dir_static.mkdir(parents=True, exist_ok=True)

    tool_used = False

    # Get plugin details directly from Plugin object
    from .constants import PLUGIN_DETAILS_BASE
    plugin_url = f"{PLUGIN_DETAILS_BASE}{plugin.plugin_id}"
    plugin_id = str(plugin.plugin_id)

    # Create synthetic path for ToolContext and logging (matches original chosen parameter)
    synthetic_path = Path(f"{synthetic_filename}.txt")

    while True:
        from .config import load_config
        config = load_config()
        tool_choice = choose_tool(config)
        if tool_choice is None:
            break

        # Get the selected tool from registry
        selected_tool = get_tool(tool_choice)

        if not selected_tool:
            warn(f"Unknown tool selection: {tool_choice}")
            continue

        _tmp_dir, oabase = build_results_paths(scan_dir, sev_dir, f"{synthetic_filename}.txt")
        results_dir = out_dir_static

        # ====================================================================
        # Tool Dispatch - Unified Context Pattern
        # ====================================================================
        # Build context once, pass to all workflows (no more per-tool params!)
        # ====================================================================

        # Special handling for metasploit (read-only from database)
        if tool_choice == "metasploit":
            from .models import Plugin
            from .database import get_connection

            if not plugin_id:
                warn("Cannot extract plugin ID from filename.")
                continue

            # Query Metasploit module names from database (no web scraping)
            try:
                header("Metasploit Module Information")

                with get_connection() as conn:
                    plugin_obj = Plugin.get_by_id(int(plugin_id), conn=conn)

                if not plugin_obj or not plugin_obj.metasploit_names:
                    warn("No Metasploit modules associated with this finding.")
                    continue

                # Display available module names
                info(f"Found {len(plugin_obj.metasploit_names)} Metasploit module(s):")
                for idx, msf_name in enumerate(plugin_obj.metasploit_names, start=1):
                    _console_global.print(f"  {idx}. {msf_name}")

                # Build list of all commands
                one_liners = []
                for msf_name in plugin_obj.metasploit_names:
                    cmd = f"msfconsole -q -x 'search {msf_name}; exit'"
                    one_liners.append(cmd)

                if plugin_obj.cves:
                    for cve in plugin_obj.cves:
                        cmd = f"msfconsole -q -x 'search {cve}; exit'"
                        one_liners.append(cmd)

                # Interactive command selection loop
                while True:
                    _console_global.print("\n[cyan]>>[/cyan] Available commands:")
                    for idx, cmd in enumerate(one_liners, start=1):
                        _console_global.print(f"  {idx}. {cmd}")

                    try:
                        answer = Prompt.ask(
                            "\nRun which command? (number or [n] None)",
                            default="n"
                        )

                        if answer and answer.strip().lower() != "n":
                            try:
                                selection = int(answer.strip())
                                if 1 <= selection <= len(one_liners):
                                    selected_cmd = one_liners[selection - 1]

                                    # Execute command with confirmation
                                    info(f"\nExecuting: {selected_cmd}\n")
                                    if Confirm.ask("Confirm?", default=False):
                                        shell_exec = shutil.which("bash") or shutil.which("sh")
                                        if shell_exec:
                                            run_command_with_progress(
                                                selected_cmd,
                                                shell=True,
                                                executable=shell_exec
                                            )
                                            ok("\nCommand completed.")
                                        else:
                                            warn("No shell found (bash/sh).")
                                    else:
                                        info("Execution skipped.")

                                    continue  # Show menu again
                                else:
                                    warn("Invalid selection.")
                                    continue
                            except ValueError:
                                warn("Invalid selection.")
                                continue
                        else:
                            break  # Exit loop
                    except (KeyboardInterrupt, EOFError):
                        info("\nReturning to menu.")
                        break
            except Exception as exc:
                warn(f"Failed to retrieve Metasploit information: {exc}")

            continue

        # Build unified context for all other tools
        ctx = ToolContext(
            tcp_ips=tcp_ips,
            udp_ips=udp_ips,
            tcp_sockets=tcp_sockets,
            ports_str=ports_str,
            use_sudo=use_sudo,
            workdir=workdir,
            results_dir=results_dir,
            oabase=oabase,
            scan_dir=scan_dir,
            sev_dir=sev_dir,
            plugin_url=plugin_url,
            chosen_file=synthetic_path,
        )

        # Call workflow with unified context (same signature for all tools!)
        result = selected_tool.workflow_builder(ctx)

        # Handle cancellation
        if result is None:
            # User cancelled - break for nmap/custom, continue for netexec
            if tool_choice in ("nmap", "custom"):
                break
            else:
                continue

        # Extract results from unified CommandResult
        cmd = result.command
        display_cmd = result.display_command
        artifact_note = result.artifact_note
        nxc_relay_path = result.relay_path

        action = command_review_menu(display_cmd)

        if action == "copy":
            cmd_str = display_cmd if isinstance(display_cmd, str) else " ".join(display_cmd)
            if copy_to_clipboard(cmd_str)[0]:
                ok("Command copied to clipboard.")
            else:
                warn(
                    "Could not copy to clipboard automatically. "
                    "Here it is to copy manually:"
                )
                _console_global.print(cmd_str)

        elif action == "run":
            try:
                tool_used = True

                # Execute command and capture metadata
                if isinstance(cmd, list):
                    exec_metadata = run_command_with_progress(cmd, shell=False)
                else:
                    shell_exec = shutil.which("bash") or shutil.which("sh")
                    exec_metadata = run_command_with_progress(cmd, shell=True, executable=shell_exec)

                # Log execution to database
                cmd_str = display_cmd if isinstance(display_cmd, str) else " ".join(str(x) for x in display_cmd)

                # Count hosts for metadata
                host_count = None
                try:
                    if tcp_ips.exists():
                        with open(tcp_ips) as f:
                            host_count = sum(1 for _ in f)
                except Exception:
                    pass

                execution_id = log_tool_execution(
                    tool_name=selected_tool.name,
                    command_text=cmd_str,
                    execution_metadata=exec_metadata,
                    tool_protocol=getattr(selected_tool, 'protocol', None),
                    host_count=host_count,
                    ports=ports_str if ports_str else None,
                    file_path=synthetic_path,
                    scan_dir=scan_dir
                )

                # Track artifacts (nmap outputs, etc.)
                if execution_id and selected_tool.name == "nmap":
                    log_artifacts_for_nmap(execution_id, oabase)

            except KeyboardInterrupt:
                warn("\nRun interrupted — returning to tool menu.")
                continue
            except subprocess.CalledProcessError as exc:
                err(f"Command exited with {exc.returncode}.")
                info("Returning to tool menu.")
                continue

        elif action == "cancel":
            info("Canceled. Returning to tool menu.")
            continue

        header("Artifacts")
        info(f"Workspace:     {workdir}")
        info(f" - Hosts:      {workdir / 'tcp_ips.list'}")
        if ports_str:
            info(f" - Host:Ports: {workdir / 'tcp_host_ports.list'}")
        info(f" - {artifact_note}")
        if nxc_relay_path:
            info(f" - Relay targets: {nxc_relay_path}")
        info(f" - Results dir:{results_dir}")

        try:
            again = Confirm.ask("\nRun another command for this finding?", default=False)
        except KeyboardInterrupt:
            break
        if not again:
            break

    return tool_used


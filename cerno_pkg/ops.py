"""External command execution and process management utilities.

This module provides functions for running external commands with progress
indicators, cloning git repositories, and checking for command availability
and privileges.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .ansi import C, err, get_console
from .constants import PROCESS_TERMINATE_TIMEOUT
from .logging_setup import log_error, log_info, log_timing


_console_global = get_console()


@dataclass
class ExecutionMetadata:
    """Metadata about a command execution.

    Attributes:
        exit_code: Command exit code
        duration_seconds: Execution time in seconds
        used_sudo: Whether command was run with sudo
    """
    exit_code: int
    duration_seconds: float
    used_sudo: bool


@dataclass
class ProxyConfig:
    """Configuration for proxychains4 SOCKS proxy routing.

    Attributes:
        enabled: Whether proxy routing is active
        host: SOCKS5 proxy host (e.g., "127.0.0.1")
        port: SOCKS5 proxy port (e.g., 9000)
    """
    enabled: bool
    host: str
    port: int


def write_proxychains_config(proxy: ProxyConfig, config_path: Path) -> None:
    """Write a proxychains4 configuration file from ProxyConfig settings.

    No-op if proxy.enabled is False.

    Overwrites any existing file at config_path when enabled. Creates parent
    directories if they do not exist.

    Args:
        proxy: Proxy configuration with host and port
        config_path: Destination path for the proxychains4.conf file

    Raises:
        ValueError: If host or port values are malformed.
    """
    if not proxy.enabled:
        return
    if "\n" in proxy.host or " " in proxy.host:
        raise ValueError(f"Invalid proxychains host: {proxy.host!r}")
    if not (0 < proxy.port < 65536):
        raise ValueError(f"Invalid proxychains port: {proxy.port}")
    content = (
        "strict_chain\n"
        "proxy_dns\n"
        "tcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n"
        "[ProxyList]\n"
        f"socks5 {proxy.host} {proxy.port}\n"
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content, encoding="utf-8")


@log_timing
def run_command_with_progress(
    cmd: list[str] | str,
    *,
    shell: bool = False,
    executable: Optional[str] = None,
    proxy_config: Optional[ProxyConfig] = None,
) -> ExecutionMetadata:
    """Execute a command with a Rich progress spinner.

    For sudo commands, prompts for password upfront to avoid interrupting
    the spinner. Streams command output in real-time.

    Args:
        cmd: Command to execute (list of args or shell string)
        shell: Whether to execute via shell
        executable: Shell executable to use (if shell=True)
        proxy_config: Optional proxy configuration. When enabled, wraps command
            with proxychains4 and writes a proxychains4.conf to ~/.cerno/.

    Returns:
        ExecutionMetadata with exit code, duration, and sudo usage

    Raises:
        subprocess.CalledProcessError: If command returns non-zero exit code
        KeyboardInterrupt: If user interrupts execution
    """
    start_time = time.time()
    display_cmd = (
        cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd)
    )
    log_info(f"Executing: {display_cmd}")
    if len(display_cmd) > 120:
        display_cmd = display_cmd[:117] + "..."

    # Delay spinner until after sudo password (if needed)
    def _cmd_starts_with_sudo(c: list[str] | str) -> bool:
        """Check if a command starts with sudo."""
        if isinstance(c, list):
            return len(c) > 0 and os.path.basename(str(c[0])) == "sudo"
        else:
            return bool(re.match(r"^\s*(?:\S*/)?sudo\b", c))

    used_sudo = _cmd_starts_with_sudo(cmd)

    try:
        if used_sudo:
            # Check if sudo is already validated (non-interactive)
            try:
                check_result = subprocess.run(
                    ["sudo", "-vn"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                needs_password = check_result.returncode != 0
            except Exception:
                needs_password = True  # be conservative

            if needs_password:
                print(
                    f"{C.YELLOW}Waiting for sudo password...{C.RESET} "
                    "(type it when prompted below)"
                )
                # Prompt the user once before launching the actual command
                try:
                    subprocess.run(["sudo", "-v"], check=True)
                except KeyboardInterrupt:
                    raise
                except subprocess.CalledProcessError as e:
                    raise subprocess.CalledProcessError(e.returncode, e.cmd)
    except Exception:
        # Non-fatal: even if pre-validation fails, fallback to normal behavior
        pass

    # Apply proxychains4 wrapping if proxy is enabled.
    # Must happen AFTER sudo detection (used_sudo checks original cmd)
    # and BEFORE Popen (so the wrapped command is what actually runs).
    if proxy_config is not None and proxy_config.enabled:
        cerno_dir = Path.home() / ".cerno"
        pc4_conf = cerno_dir / "proxychains4.conf"
        write_proxychains_config(proxy_config, pc4_conf)
        if isinstance(cmd, list):
            cmd = ["proxychains4", "-f", str(pc4_conf)] + list(cmd)
        else:
            cmd = f"proxychains4 -f {shlex.quote(str(pc4_conf))} {cmd}"
        log_info(
            f"Proxy: routing through SOCKS5 "
            f"{proxy_config.host}:{proxy_config.port} via proxychains4"
        )
        get_console().print(
            f"[proxy] Routing through SOCKS5 "
            f"{proxy_config.host}:{proxy_config.port} via proxychains4"
        )

    if isinstance(cmd, list):
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    else:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            executable=executable,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    try:
        from .ansi import style_if_enabled
        if proc.stdout is None:
            # This should never happen since we set stdout=PIPE, but satisfy type checker
            proc.wait()
            return_code = proc.returncode
        else:
            with Progress(
                SpinnerColumn(style=style_if_enabled("cyan")),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                progress.add_task(f"Running: {display_cmd}", start=True)
                for line in iter(proc.stdout.readline, ""):
                    print(line, end="")
                    progress.refresh()
                proc.stdout.close()
                proc.wait()
                return_code = proc.returncode
    except KeyboardInterrupt:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=PROCESS_TERMINATE_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
        finally:
            raise

    duration = time.time() - start_time

    if return_code != 0:
        log_error(f"Command failed with rc={return_code}")
        raise subprocess.CalledProcessError(return_code, cmd)
    log_info(f"Command succeeded with rc={return_code}")

    return ExecutionMetadata(
        exit_code=return_code,
        duration_seconds=duration,
        used_sudo=used_sudo
    )


@log_timing
def root_or_sudo_available() -> bool:
    """Check if running as root or if sudo is available.

    Returns:
        True if running as root (on Unix) or sudo command is available
    """
    try:
        if os.name != "nt" and os.geteuid() == 0:  # type: ignore[attr-defined]
            return True
    except AttributeError:
        pass
    return shutil.which("sudo") is not None


def require_cmd(name: str) -> None:
    """Ensure a required command is available on PATH.

    Args:
        name: Command name to check for

    Raises:
        SystemExit: If command is not found on PATH
    """
    if shutil.which(name) is None:
        err(f"Required command '{name}' not found on PATH.")
        sys.exit(1)


def resolve_cmd(candidates: list[str]) -> Optional[str]:
    """Find the first available command from a list of candidates.

    Args:
        candidates: List of command names to try

    Returns:
        First command found on PATH, or None if none are available
    """
    for candidate in candidates:
        if shutil.which(candidate):
            return candidate
    return None


def get_tool_version(tool_name: str, candidates: Optional[list[str]] = None) -> Optional[str]:
    """Get version string for a tool by executing it with --version flag.

    Tries to detect the version of an installed tool by running it with the
    --version flag and parsing the output. Supports multiple binary name
    candidates (e.g., "nxc" or "netexec" for the same tool).

    Args:
        tool_name: Primary tool name to check
        candidates: Optional list of alternative binary names to try

    Returns:
        Version string (e.g., "7.92") if successful, None if tool not found
        or version cannot be determined

    Examples:
        >>> get_tool_version("nmap")
        "7.92"
        >>> get_tool_version("netexec", ["nxc", "netexec"])
        "1.2.1"
        >>> get_tool_version("missing_tool")
        None
    """
    from .logging_setup import log_debug

    # Determine which binaries to try
    binaries_to_try = candidates if candidates else [tool_name]

    # Try each binary candidate
    for binary in binaries_to_try:
        # Check if binary exists first
        if not shutil.which(binary):
            continue

        try:
            # Run tool with --version flag
            result = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode != 0:
                # Some tools output version to stderr
                output = result.stdout + result.stderr
            else:
                output = result.stdout

            # Parse version from output using regex patterns
            # Pattern 1: "Nmap version 7.92" or "version 1.2.1"
            match = re.search(r"(?:version\s+)?(\d+\.\d+(?:\.\d+)?)", output, re.IGNORECASE)
            if match:
                version = match.group(1)
                log_debug(f"Detected {binary} version: {version}")
                return version

            # If no version pattern found, log and continue to next candidate
            log_debug(f"Could not parse version from {binary} --version output")

        except subprocess.TimeoutExpired:
            log_debug(f"Timeout getting version for {binary}")
        except Exception as exc:
            log_debug(f"Error getting version for {binary}: {exc}")

    # No version detected for any candidate
    return None


def log_tool_execution(
    tool_name: str,
    command_text: str,
    execution_metadata: ExecutionMetadata,
    *,
    tool_protocol: Optional[str] = None,
    host_count: Optional[int] = None,
    sampled: bool = False,
    ports: Optional[str] = None,
    file_path: Optional[Path] = None,
    scan_dir: Optional[Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[int]:
    """Log a tool execution to the database.

    Args:
        tool_name: Name of the tool (nmap, netexec, etc.)
        command_text: Full command that was executed
        execution_metadata: Metadata from command execution
        tool_protocol: Protocol for netexec (smb, rdp, etc.)
        host_count: Number of hosts targeted
        sampled: Whether host list was sampled
        ports: Port specification string
        file_path: Path to plugin file being processed
        scan_dir: Scan directory for session linking
        conn: Optional database connection. If None, creates new connection.
              Useful for testing or including in larger transactions.

    Returns:
        execution_id if successful, None otherwise
    """
    if conn is not None:
        # Use provided connection (testing or transaction)
        return _log_tool_execution_impl(
            conn, tool_name, command_text, execution_metadata,
            tool_protocol, host_count, sampled, ports, file_path, scan_dir
        )

    # Production path: create new connection
    try:
        from .database import db_transaction
        with db_transaction() as new_conn:
            return _log_tool_execution_impl(
                new_conn, tool_name, command_text, execution_metadata,
                tool_protocol, host_count, sampled, ports, file_path, scan_dir
            )
    except Exception as e:
        log_error(f"Failed to log tool execution to database: {e}")
        return None


def _log_tool_execution_impl(
    conn: sqlite3.Connection,
    tool_name: str,
    command_text: str,
    execution_metadata: ExecutionMetadata,
    tool_protocol: Optional[str],
    host_count: Optional[int],
    sampled: bool,
    ports: Optional[str],
    file_path: Optional[Path],
    scan_dir: Optional[Path],
) -> Optional[int]:
    """Internal implementation of log_tool_execution - requires connection.

    Args:
        conn: Database connection
        (other args same as log_tool_execution)

    Returns:
        execution_id if successful, None otherwise
    """
    try:
        from .database import query_one
        from .models import ToolExecution, now_iso

        # Determine session_id and finding_id
        session_id = None
        finding_id = None

        if scan_dir and scan_dir.exists():
            # Try to find active session
            scan_name = scan_dir.name
            row = query_one(
                conn,
                """
                SELECT s.session_id
                FROM sessions s
                JOIN scans sc ON s.scan_id = sc.scan_id
                WHERE sc.scan_name = ? AND s.session_end IS NULL
                ORDER BY s.session_start DESC LIMIT 1
                """,
                (scan_name,)
            )
            if row:
                session_id = row["session_id"]

        # Note: finding_id is optional and can remain None
        # File paths are not stored in the database - findings are referenced by IDs
        # Tool executions are still tracked, just not linked to specific findings

        # Create tool execution record
        tool_exec = ToolExecution(
            session_id=session_id,
            finding_id=finding_id,
            tool_name=tool_name,
            tool_protocol=tool_protocol,
            command_text=command_text,
            executed_at=now_iso(),
            exit_code=execution_metadata.exit_code,
            duration_seconds=execution_metadata.duration_seconds,
            host_count=host_count,
            sampled=sampled,
            ports=ports,
            used_sudo=execution_metadata.used_sudo
        )

        execution_id = tool_exec.save(conn)
        log_info(f"Logged tool execution to database (ID: {execution_id})")
        return execution_id

    except Exception as e:
        log_error(f"Failed to log tool execution to database (impl): {e}")
        return None


def log_artifact(
    execution_id: int,
    artifact_path: Path,
    artifact_type: str,
    metadata: Optional[dict] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[int]:
    """Log an artifact file to the database.

    Args:
        execution_id: Tool execution ID that created this artifact
        artifact_path: Path to artifact file
        artifact_type: Type of artifact (nmap_xml, nmap_nmap, nmap_gnmap, log, etc.)
        metadata: Optional metadata dictionary (tool-specific info)
        conn: Optional database connection. If None, creates new connection.
              Useful for testing or including in larger transactions.

    Returns:
        artifact_id if successful, None otherwise
    """
    if conn is not None:
        # Use provided connection (testing or transaction)
        return _log_artifact_impl(conn, execution_id, artifact_path, artifact_type, metadata)

    # Production path: create new connection
    try:
        from .database import db_transaction
        with db_transaction() as new_conn:
            return _log_artifact_impl(new_conn, execution_id, artifact_path, artifact_type, metadata)
    except Exception as e:
        log_error(f"Failed to log artifact to database: {e}")
        return None


def _log_artifact_impl(
    conn: sqlite3.Connection,
    execution_id: int,
    artifact_path: Path,
    artifact_type: str,
    metadata: Optional[dict],
) -> Optional[int]:
    """Internal implementation of log_artifact - requires connection.

    Args:
        conn: Database connection
        (other args same as log_artifact)

    Returns:
        artifact_id if successful, None otherwise
    """
    try:
        from .database import compute_file_hash, query_one
        from .models import Artifact, now_iso

        # Look up artifact_type_id from artifact_types lookup table
        row = query_one(
            conn,
            "SELECT artifact_type_id FROM artifact_types WHERE type_name = ?",
            (artifact_type,)
        )
        if not row:
            log_error(f"Unknown artifact type: {artifact_type}")
            return None
        artifact_type_id = row["artifact_type_id"]

        # Compute file stats if file exists
        file_size = None
        file_hash = None
        if artifact_path.exists():
            file_size = artifact_path.stat().st_size
            file_hash = compute_file_hash(artifact_path)

        artifact = Artifact(
            execution_id=execution_id,
            artifact_path=str(artifact_path.resolve()),
            artifact_type_id=artifact_type_id,
            file_size_bytes=file_size,
            file_hash=file_hash,
            created_at=now_iso(),
            metadata=metadata
        )

        artifact_id = artifact.save(conn)
        log_info(f"Logged artifact to database: {artifact_path.name} (ID: {artifact_id})")
        return artifact_id

    except Exception as e:
        log_error(f"Failed to log artifact to database (impl): {e}")
        return None


def log_artifacts_for_nmap(
    execution_id: int,
    oabase: Path,
    metadata: Optional[dict] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[int]:
    """Log nmap output artifacts (-oA outputs) to database.

    Args:
        execution_id: Tool execution ID
        oabase: Base path for -oA output (without extension)
        metadata: Optional metadata
        conn: Optional database connection. If None, creates new connection.
              Useful for testing or including in larger transactions.

    Returns:
        List of artifact IDs created
    """
    artifact_ids = []

    # Check for standard nmap output formats
    output_formats = [
        (".xml", "nmap_xml"),
        (".nmap", "nmap_nmap"),
        (".gnmap", "nmap_gnmap"),
    ]

    for ext, artifact_type in output_formats:
        artifact_path = Path(str(oabase) + ext)
        if artifact_path.exists():
            artifact_id = log_artifact(execution_id, artifact_path, artifact_type, metadata, conn=conn)
            if artifact_id:
                artifact_ids.append(artifact_id)

    return artifact_ids


def get_interface_ip(interface: str) -> Optional[str]:
    """Return the IPv4 address of a network interface, or None if unavailable.

    Args:
        interface: Interface name (e.g. 'tun0', 'eth0')

    Returns:
        IPv4 address string in dotted-quad format, or None
    """
    import socket
    import struct
    import fcntl
    SIOCGIFADDR = 0x8915
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            result = fcntl.ioctl(
                s.fileno(),
                SIOCGIFADDR,
                struct.pack("256s", interface[:15].encode()),
            )
        return socket.inet_ntoa(result[20:24])
    except OSError:
        return None


def list_interfaces() -> list[tuple[str, str]]:
    """Return all network interfaces that have an IPv4 address.

    Returns:
        List of (interface_name, ip_address) tuples, loopback last.
    """
    import os
    try:
        names = os.listdir("/sys/class/net/")
    except OSError:
        return []

    interfaces = []
    for name in sorted(names):
        ip = get_interface_ip(name)
        if ip:
            interfaces.append((name, ip))

    # Move loopback to end so it doesn't dominate the picker
    interfaces.sort(key=lambda x: x[0] == "lo")
    return interfaces


def start_ips_server(ips_path: Path, port: int) -> tuple["http.server.HTTPServer", "threading.Thread"]:
    """Start a temporary HTTP server serving the IP list at /ips.txt.

    The server binds to 0.0.0.0 and serves ONLY GET /ips.txt — all other
    paths return 404. No directory listing.

    Args:
        ips_path: Path to the tcp_ips.list file to serve
        port: Port to listen on

    Returns:
        (server, thread) — call server.shutdown() to stop.
    """
    import http.server
    import threading

    _ips_path = ips_path  # capture for closure

    class _IpsHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/ips.txt":
                try:
                    content = _ips_path.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                except OSError:
                    self.send_error(500, "Could not read IP list")
            else:
                self.send_error(404, "Not found")

        def log_message(self, format: str, *args: object) -> None:
            pass  # Suppress request logging to terminal

    server = http.server.HTTPServer(("0.0.0.0", port), _IpsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def build_nmap_remote_oneliner(
    server_ip: str,
    server_port: int,
    ports_str: str,
    nse_option: str,
    timestamp: str,
) -> str:
    """Build the curl+nmap one-liner for remote scan mode.

    The operator pastes this into a shell on the pivot host.
    Requires root (sudo) on the pivot for -sS.

    Args:
        server_ip: IP address of the cerno HTTP server (from pivot_interface)
        server_port: Port of the cerno HTTP server
        ports_str: Comma-separated ports string (e.g. '445,139') or empty string
        nse_option: NSE option string (e.g. '--script=smb-vuln-ms17-010') or empty string
        timestamp: Timestamp string for output filename (e.g. '20260416_143022')

    Returns:
        Complete one-liner command string
    """
    output_path = f"/tmp/cerno_{timestamp}"
    nmap_parts = ["sudo", "nmap", "-sS", "-A", "-iL", "-"]
    if ports_str:
        nmap_parts += ["-p", ports_str]
    if nse_option:
        nmap_parts.append(nse_option)
    nmap_parts += ["-oA", output_path]
    return f"curl -s http://{server_ip}:{server_port}/ips.txt | " + " ".join(nmap_parts)
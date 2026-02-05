"""Nessus .nessus XML parsing and database import functionality.

Parses Nessus .nessus XML files and imports findings into the SQLite database.

Adapted from DefensiveOrigins/NessusPluginHosts
Repository: https://github.com/DefensiveOrigins/NessusPluginHosts
Contributors: DefensiveOrigins, ChrisTraynor

Integrated into cerno with enhancements:
- Type hints and comprehensive docstrings
- Integration with cerno's logging infrastructure
- Database-first import (no file creation required)
- Rich progress reporting support
- Cleaner API design for programmatic use
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from .ansi import err, info
from .logging_setup import log_error, log_info, log_timing

# Severity labels for integer severity levels (0-4)
SEV_LABELS: Tuple[str, ...] = ("Info", "Low", "Medium", "High", "Critical")


@dataclass
class ExportResult:
    """Result of Nessus plugin export operation.

    Attributes:
        plugins_exported: Total number of plugins exported
        total_hosts: Total number of unique host:port combinations
        scan_name: Name of the scan (derived from .nessus filename)
        severities: Mapping of severity level to plugin count
    """
    plugins_exported: int
    total_hosts: int
    scan_name: str
    severities: Dict[int, int]


@dataclass
class HostMetadata:
    """Metadata about a host extracted from Nessus HostProperties.

    Captures the full host context from Nessus scans, supporting both
    IP-targeted (internal) and FQDN-targeted (external) scans.

    Attributes:
        host_ip: Resolved IP address (from host-ip tag, always present)
        scan_target: What was scanned (ReportHost@name - IP or FQDN)
        netbios_name: NetBIOS/computer name (from netbios-name tag)
        fqdn: FQDN from Nessus discovery (from host-fqdn tag)
        reverse_dns: Reverse DNS result (from host-rdns tag)
    """
    host_ip: str
    scan_target: str
    netbios_name: Optional[str] = None
    fqdn: Optional[str] = None
    reverse_dns: Optional[str] = None


def is_ip(entry: str) -> bool:
    """Check if a host entry is an IP address.

    Args:
        entry: Host entry, potentially with port (e.g., "192.168.1.1:80")

    Returns:
        True if the host part is a valid IPv4 or IPv6 address
    """
    try:
        ipaddress.ip_address(entry.split(":")[0])
        return True
    except ValueError:
        return False


def sort_key_ip(entry: str) -> Tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    """Generate sort key for IP address entries.

    Sorts by IP address (natural ordering) then port number.

    Args:
        entry: Host:port string (e.g., "192.168.1.1:80")

    Returns:
        Tuple of (IP address object, port number) for sorting
    """
    ip_part, port_part = (entry.split(":") + ["0"])[:2]
    return (ipaddress.ip_address(ip_part), int(port_part))


def severity_label_from_int(sev_int: int) -> str:
    """Convert severity integer to human-readable label.

    Args:
        sev_int: Severity level (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)

    Returns:
        Severity label string, or "Unknown" if out of range
    """
    if 0 <= sev_int < len(SEV_LABELS):
        return SEV_LABELS[sev_int]
    return "Unknown"


def cvss_to_sev(cvss_score: Optional[str]) -> int:
    """Map CVSS base score to severity bucket.

    CVSS v3 is preferred, with fallback to v2. Mapping:
      - 0.0            -> 0 (Info)
      - 0.1 - 3.9      -> 1 (Low)
      - 4.0 - 6.9      -> 2 (Medium)
      - 7.0 - 8.9      -> 3 (High)
      - 9.0 - 10.0     -> 4 (Critical)

    Args:
        cvss_score: CVSS score as string, or None if missing

    Returns:
        Severity integer (0-4), defaults to 0 if score is missing or invalid
    """
    if cvss_score is None:
        return 0  # Default to Info if score missing
    try:
        s = float(cvss_score)
    except (TypeError, ValueError):
        return 0  # Default to Info if score unparsable

    if s == 0.0:
        return 0
    if 0.0 < s <= 3.9:
        return 1
    if 4.0 <= s <= 6.9:
        return 2
    if 7.0 <= s <= 8.9:
        return 3
    return 4  # >= 9.0


def sanitize_filename(name: str, max_len: int = 80) -> str:
    """Sanitize a string for safe filesystem use.

    Replaces invalid characters with underscores, collapses multiple spaces,
    and enforces maximum length.

    Args:
        name: Raw string to sanitize
        max_len: Maximum filename length (default 80)

    Returns:
        Filesystem-safe string with invalid chars replaced by underscores
    """
    safe = "".join(
        c if (c.isalnum() or c in "-_ .") else "_"
        for c in (name or "").strip()
    )
    safe = "_".join(safe.split())  # Collapse multiple spaces

    if not safe:
        safe = "plugin"

    if len(safe) > max_len:
        safe = safe[:max_len].rstrip("_")

    return safe


def extract_scan_name_from_nessus(nessus_file: Path) -> str:
    """Extract scan name from .nessus XML file.

    Tries to extract the Report[@name] attribute from the XML. If not found
    or if parsing fails, falls back to using the .nessus filename stem.
    The result is sanitized for use as a directory name.

    Args:
        nessus_file: Path to .nessus XML file

    Returns:
        Sanitized scan name suitable for use as a directory name

    Example:
        >>> extract_scan_name_from_nessus(Path("GOAD.nessus"))
        'GOAD'
        >>> # If Report name="Internal Scan 2024" in XML
        >>> extract_scan_name_from_nessus(Path("scan.nessus"))
        'Internal_Scan_2024'
    """
    try:
        # Try to extract Report name attribute from XML
        tree = ET.parse(nessus_file)
        root = tree.getroot()

        # Find <Report name="..."> element
        report_elem = root.find("Report")
        if report_elem is not None:
            scan_name = report_elem.get("name")
            if scan_name:
                log_info(f"Extracted scan name from Report element: {scan_name}")
                return sanitize_filename(scan_name)

    except Exception as e:
        log_error(f"Failed to parse .nessus file for scan name: {e}")

    # Fallback to filename stem
    fallback = nessus_file.stem
    log_info(f"Using filename stem as scan name: {fallback}")
    return sanitize_filename(fallback)


def truthy(text: Optional[str]) -> bool:
    """Convert XML text content to boolean.

    Args:
        text: XML text value to interpret as boolean

    Returns:
        True if text is "true", "yes", or "1" (case-insensitive)
    """
    return text is not None and text.strip().lower() in ("true", "yes", "1")


def _build_index_stream(
    filename: Path,
    include_ports: bool = True
) -> Tuple[Dict[str, dict], Dict[str, Set[Tuple[str, str]]], Dict[str, HostMetadata], Set[Tuple[str, str, str, str]]]:
    """Parse .nessus XML file and build plugin index with streaming.

    Memory-efficient single-pass parsing using iterparse with element clearing.

    Args:
        filename: Path to .nessus XML file
        include_ports: Whether to include port numbers in host entries

    Returns:
        Tuple of:
          - plugins dict: plugin_id -> {name, severity_int, msf}
          - plugin_hosts dict: plugin_id -> set of host entries
          - host_metadata dict: scan_target -> HostMetadata
          - service_entries set: (scan_target, port, protocol, svc_name) tuples

    Raises:
        ET.ParseError: If XML parsing fails
        FileNotFoundError: If .nessus file doesn't exist
    """
    plugins: Dict[str, dict] = {}
    plugin_hosts: Dict[str, Set[tuple[str, str]]] = defaultdict(set)
    host_metadata: Dict[str, HostMetadata] = {}
    service_entries: Set[Tuple[str, str, str, str]] = set()
    current_host = ""
    current_host_properties: Dict[str, Optional[str]] = {}
    in_host_properties = False

    try:
        for event, elem in ET.iterparse(filename, events=("start", "end")):
            tag = elem.tag

            # Track current host being processed
            if event == "start" and tag == "ReportHost":
                current_host = elem.attrib.get("name", "")
                current_host_properties = {}

            # Track when we're inside HostProperties
            elif event == "start" and tag == "HostProperties":
                in_host_properties = True

            elif event == "end" and tag == "HostProperties":
                in_host_properties = False

            # Capture HostProperties tags (tag elements inside HostProperties)
            elif event == "end" and tag == "tag" and in_host_properties:
                tag_name = elem.attrib.get("name", "")
                tag_value = elem.text.strip() if elem.text else None
                if tag_name and current_host:
                    current_host_properties[tag_name] = tag_value

            # Process each plugin finding
            elif event == "end" and tag == "ReportItem":
                pid = elem.attrib.get("pluginID")
                if not pid:
                    elem.clear()
                    continue

                # Severity: prefer CVSS v3, fallback to CVSS v2
                cvss = elem.findtext("cvss3_base_score")
                if not cvss:
                    cvss = elem.findtext("cvss_base_score")
                sev_int = cvss_to_sev(cvss)

                # Check for Metasploit module availability
                msf_flag = truthy(elem.findtext("exploit_framework_metasploit"))

                # Extract CVE tags from XML
                cve_elements = elem.findall("cve")
                cve_list: list[str] = []
                for cve_elem in cve_elements:
                    if cve_elem.text:
                        cve_text = cve_elem.text.strip().upper()
                        # Validate CVE format: CVE-YYYY-NNNNN
                        if re.match(r'^CVE-\d{4}-\d{4,}$', cve_text):
                            cve_list.append(cve_text)
                # Sort and deduplicate CVEs
                cves: list[str] | None = sorted(set(cve_list)) if cve_list else None

                # Extract Metasploit module names from XML
                msf_name_elements = elem.findall("metasploit_name")
                msf_name_list: list[str] = []
                for msf_elem in msf_name_elements:
                    if msf_elem.text:
                        name = msf_elem.text.strip()
                        if name:
                            msf_name_list.append(name)
                # Sort and deduplicate module names
                msf_names: list[str] | None = sorted(set(msf_name_list)) if msf_name_list else None

                # Extract plugin_output from XML
                plugin_output_elem = elem.find("plugin_output")
                plugin_output = None
                if plugin_output_elem is not None and plugin_output_elem.text:
                    plugin_output = plugin_output_elem.text.strip()

                # Store or merge plugin metadata (keep highest severity)
                pname = (elem.attrib.get("pluginName") or "").strip()
                existing = plugins.get(pid)

                if existing is None:
                    plugins[pid] = {
                        "name": pname,
                        "severity_int": sev_int,
                        "msf": msf_flag,
                        "msf_names": msf_names,
                        "cves": cves,
                    }
                else:
                    # Keep highest severity across all instances
                    if sev_int > existing["severity_int"]:
                        existing["severity_int"] = sev_int
                    # Merge MSF flag (any True wins)
                    if msf_flag:
                        existing["msf"] = True
                    # Fill name if previously blank
                    if not existing.get("name") and pname:
                        existing["name"] = pname
                    # Merge Metasploit module names (deduplicate)
                    if msf_names:
                        existing_names = existing.get("msf_names") or []
                        merged_names = list(set(existing_names + msf_names))
                        existing["msf_names"] = sorted(merged_names) if merged_names else None
                    # Merge CVEs (deduplicate)
                    if cves:
                        existing_cves = existing.get("cves") or []
                        merged_cves = list(set(existing_cves + cves))
                        existing["cves"] = sorted(merged_cves) if merged_cves else None

                # Record host:port combination with plugin_output
                port = elem.attrib.get("port", "0")
                entry = current_host if (not include_ports or port == "0") else f"{current_host}:{port}"
                plugin_hosts[pid].add((entry, plugin_output or ""))

                # Collect service mapping for host_services table
                svc_name = elem.attrib.get("svc_name", "")
                protocol_attr = elem.attrib.get("protocol", "tcp")
                if port != "0" and svc_name and svc_name != "general" and current_host:
                    service_entries.add((current_host, port, protocol_attr, svc_name))

                elem.clear()  # Free memory immediately

            # Clean up after processing host - build HostMetadata
            elif event == "end" and tag == "ReportHost":
                if current_host:
                    # Build HostMetadata from collected properties
                    # host-ip is the resolved IP; scan_target is ReportHost@name
                    host_ip = current_host_properties.get("host-ip")

                    # If no host-ip tag, fall back to scan_target (IP-targeted scans)
                    if not host_ip:
                        host_ip = current_host

                    host_metadata[current_host] = HostMetadata(
                        host_ip=host_ip,
                        scan_target=current_host,
                        netbios_name=current_host_properties.get("netbios-name"),
                        fqdn=current_host_properties.get("host-fqdn"),
                        reverse_dns=current_host_properties.get("host-rdns")
                    )

                elem.clear()
                current_host = ""
                current_host_properties = {}

        return plugins, plugin_hosts, host_metadata, service_entries

    except ET.ParseError as e:
        log_error(f"Failed to parse {filename} as XML: {e}")
        err(f"Error: Could not parse {filename} as XML.")
        raise
    except FileNotFoundError as e:
        log_error(f"Nessus file not found: {filename}")
        err(f"Error: File {filename} not found.")
        raise


@log_timing
def import_nessus_file(
    nessus_file: Path,
    output_dir: Path,
    *,
    scan_name: Optional[str] = None,
    include_ports: bool = True,
    use_database: bool = True
) -> ExportResult:
    """Import Nessus scan from .nessus file into database.

    Parses the .nessus XML file and populates the database with:
    - Scan metadata (scan name, file path, hash)
    - Plugin information (ID, name, severity, CVEs, Metasploit modules)
    - Plugin files per scan (host counts, port counts, review state)
    - Host:port combinations with plugin output

    The output_dir parameter is used to set the scan's export_root in the database,
    but no actual files are created (database-only mode).

    Args:
        nessus_file: Path to .nessus XML file to parse
        output_dir: Root directory path (stored in database but no files created)
        scan_name: Optional scan name (defaults to nessus_file.stem if not provided)
        include_ports: Whether to include port numbers in host listings (default: True)
        use_database: Whether to write metadata to database (default: True)

    Returns:
        ExportResult with import statistics

    Raises:
        ET.ParseError: If XML parsing fails
        FileNotFoundError: If .nessus file doesn't exist
    """
    log_info(f"Importing Nessus scan from {nessus_file}")

    # Parse .nessus file
    plugins, plugin_hosts, host_metadata, service_entries = _build_index_stream(nessus_file, include_ports)

    if not plugins:
        log_info("No plugins with findings found in .nessus file")
        info("No plugins with findings found.")
        return ExportResult(
            plugins_exported=0,
            total_hosts=0,
            scan_name=scan_name or nessus_file.stem,
            severities={}
        )

    # Prepare export directory structure
    # Use provided scan_name or fall back to sanitized file stem
    if scan_name is None:
        scan_name = sanitize_filename(nessus_file.stem)
    base_scan_dir = output_dir / scan_name

    # Sort plugins: severity descending, then plugin ID ascending
    def sort_key(item: Tuple[str, dict]) -> Tuple[int, int]:
        pid, meta = item
        try:
            pid_int = int(pid)
        except ValueError:
            pid_int = 999999999  # Large value for non-numeric plugin IDs
        return (-meta["severity_int"], pid_int)

    # Track statistics
    total_hosts = 0
    severities: Dict[int, int] = {}

    # Export each plugin (DATABASE-ONLY MODE - no file creation)
    for pid, meta in sorted(plugins.items(), key=sort_key):
        # Generate virtual file path for database reference (no actual file created)
        msf_suffix = "-MSF" if meta.get("msf") else ""
        f"{pid}_{sanitize_filename(meta['name'])}{msf_suffix}.txt"

        # Count hosts for statistics
        hosts = plugin_hosts.get(pid, set())
        total_hosts += len(hosts)
        severities[meta["severity_int"]] = severities.get(meta["severity_int"], 0) + 1

    log_info(f"Database-only import complete: {len(plugins)} plugins, {total_hosts} host entries (no files created)")

    # Write to database if enabled
    if use_database:
        _write_to_database(
            nessus_file=nessus_file,
            scan_name=scan_name,
            base_scan_dir=base_scan_dir,
            plugins=plugins,
            plugin_hosts=plugin_hosts,
            host_metadata=host_metadata,
            service_entries=service_entries
        )

    return ExportResult(
        plugins_exported=len(plugins),
        total_hosts=total_hosts,
        scan_name=scan_name,
        severities=severities
    )


# ========== Database Integration ==========

def _write_to_database(
    nessus_file: Path,
    scan_name: str,
    base_scan_dir: Path,
    plugins: Dict[str, dict],
    plugin_hosts: Dict[str, Set[Tuple[str, str]]],
    host_metadata: Dict[str, HostMetadata],
    service_entries: Set[Tuple[str, str, str, str]] = frozenset(),  # type: ignore[assignment]
) -> None:
    """Write scan, plugin, and host data to database.

    Args:
        nessus_file: Path to original .nessus file
        scan_name: Sanitized scan name
        base_scan_dir: Base directory where plugin files are exported
        plugins: Plugin metadata dictionary
        plugin_hosts: Plugin hosts dictionary (plugin_id -> set of host:port entries)
        host_metadata: Host metadata dictionary (scan_target -> HostMetadata)
        service_entries: Set of (scan_target, port, protocol, svc_name) tuples
    """
    try:
        from .database import db_transaction, compute_file_hash
        from .models import Scan, Plugin, Finding, now_iso
        from .parsing import detect_host_type
        import time

        start_time = time.time()
        log_info("Writing metadata to database...")

        with db_transaction() as conn:
            # Create or update scan
            nessus_hash = compute_file_hash(nessus_file) if nessus_file.exists() else None

            scan = Scan(
                scan_name=scan_name,
                nessus_file_path=str(nessus_file.resolve()),
                nessus_file_hash=nessus_hash,
                export_root=str(base_scan_dir.parent),
                created_at=now_iso()
            )

            # Check if scan exists
            existing_scan = Scan.get_by_name(scan_name, conn)
            if existing_scan:
                scan.scan_id = existing_scan.scan_id
                # Preserve original metadata when updating (prevents hash mismatch on re-import)
                scan.created_at = existing_scan.created_at
                scan.nessus_file_hash = existing_scan.nessus_file_hash
                scan.nessus_file_path = existing_scan.nessus_file_path
                log_info(f"Updating existing scan: {scan_name}")
            else:
                log_info(f"Creating new scan: {scan_name}")

            scan_id = scan.save(conn)
            if scan_id is None:
                log_error("Failed to save scan - scan_id is None")
                return

            # ========== Step 1: Collect unique hosts and ports from ALL plugins ==========
            # Use (ip_address, scan_target) as composite key for hosts
            unique_hosts: Dict[Tuple[str, str], HostMetadata] = {}  # (ip, target) -> metadata
            unique_ports: Set[int] = set()

            for plugin_id_str, meta in plugins.items():
                hosts_data = plugin_hosts.get(plugin_id_str, set())

                for host_entry_data in hosts_data:
                    # Parse host:port (existing logic)
                    host_entry, plugin_output = host_entry_data

                    # Parse host:port - host_entry contains scan_target (possibly with port)
                    if ":" in host_entry:
                        scan_target, port_str = host_entry.rsplit(":", 1)
                        try:
                            port = int(port_str)
                        except ValueError:
                            scan_target = host_entry
                            port = None
                    else:
                        scan_target = host_entry
                        port = None

                    # Get host metadata for this scan_target
                    meta_entry = host_metadata.get(scan_target)
                    if meta_entry:
                        ip_address = meta_entry.host_ip
                    else:
                        # Fallback: scan_target is the IP itself
                        ip_address = scan_target

                    # Add to unique hosts using composite key
                    composite_key = (ip_address, scan_target)
                    if composite_key not in unique_hosts:
                        if meta_entry:
                            unique_hosts[composite_key] = meta_entry
                        else:
                            # Create metadata from scan_target (IP-targeted scan)
                            unique_hosts[composite_key] = HostMetadata(
                                host_ip=ip_address,
                                scan_target=scan_target
                            )

                    if port:
                        unique_ports.add(port)

            # ========== Step 2: Bulk insert hosts with new schema ==========
            if unique_hosts:
                log_info(f"Inserting {len(unique_hosts)} unique hosts...")
                host_records = []
                for (ip_addr, scan_tgt), meta_entry in unique_hosts.items():
                    # Determine scan_target_type
                    scan_target_type = detect_host_type(scan_tgt)
                    # Convert 'hostname' to 'fqdn' for the new schema
                    if scan_target_type == 'hostname':
                        scan_target_type = 'fqdn'

                    host_records.append((
                        ip_addr,
                        scan_tgt,
                        scan_target_type,
                        meta_entry.netbios_name,
                        meta_entry.fqdn,
                        meta_entry.reverse_dns
                    ))

                conn.executemany(
                    """INSERT OR IGNORE INTO hosts
                       (ip_address, scan_target, scan_target_type, netbios_name, fqdn, reverse_dns)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    host_records
                )

            # ========== Step 3: Bulk insert ports ==========
            if unique_ports:
                log_info(f"Inserting {len(unique_ports)} unique ports...")
                conn.executemany(
                    "INSERT OR IGNORE INTO ports (port_number) VALUES (?)",
                    [(p,) for p in unique_ports]
                )

            # ========== Step 4: Build host_id lookup map using composite key ==========
            host_id_map: Dict[Tuple[str, str], int] = {}
            if unique_hosts:
                # Query all hosts we just inserted
                cursor = conn.execute(
                    "SELECT host_id, ip_address, scan_target FROM hosts"
                )
                for row in cursor.fetchall():
                    host_id_map[(row[1], row[2])] = row[0]

            # ========== Step 4.5: Bulk insert host_services ==========
            if service_entries:
                log_info(f"Inserting {len(service_entries)} service mappings...")
                service_records = []
                for scan_target_entry, port_str, protocol_val, svc_name_val in service_entries:
                    # Resolve scan_target to host_id using metadata
                    meta_entry = host_metadata.get(scan_target_entry)
                    if meta_entry:
                        ip_address = meta_entry.host_ip
                    else:
                        ip_address = scan_target_entry

                    composite_key = (ip_address, scan_target_entry)
                    host_id = host_id_map.get(composite_key)

                    try:
                        port_int = int(port_str)
                    except ValueError:
                        continue

                    if host_id and port_int:
                        service_records.append((
                            scan_id, host_id, port_int, protocol_val, svc_name_val
                        ))

                if service_records:
                    conn.executemany(
                        """INSERT OR IGNORE INTO host_services
                           (scan_id, host_id, port_number, protocol, svc_name)
                           VALUES (?, ?, ?, ?, ?)""",
                        service_records
                    )

            # ========== Step 5: Insert plugins and plugin files ==========
            total_plugins = len(plugins)
            for idx, (plugin_id_str, meta) in enumerate(plugins.items(), 1):
                plugin_id = int(plugin_id_str)

                # Show progress every 10 plugins or at milestones
                if idx % 10 == 0 or idx == total_plugins:
                    log_info(f"Processing plugin {idx}/{total_plugins}...")

                # Create plugin metadata
                plugin = Plugin(
                    plugin_id=plugin_id,
                    plugin_name=meta["name"],
                    severity_int=meta["severity_int"],
                    has_metasploit=meta.get("msf", False),
                    cvss3_score=meta.get("cvss3"),
                    cvss2_score=meta.get("cvss2"),
                    metasploit_names=meta.get("msf_names"),
                    cves=meta.get("cves"),
                    plugin_url=f"https://www.tenable.com/plugins/nessus/{plugin_id}"
                )
                plugin.save(conn)

                # Create plugin file entry
                hosts_data = plugin_hosts.get(plugin_id_str, set())

                # Count unique hosts and ports for this plugin
                unique_hosts_for_plugin = set()
                ports_for_plugin = set()
                for host_entry_data in hosts_data:
                    # Unpack tuple to get host_entry string (ignore plugin_output for counting)
                    host_entry, _ = host_entry_data  # Extract host:port, ignore plugin_output

                    # Now parse host:port as before
                    if ":" in host_entry:
                        try:
                            host, port_str = host_entry.rsplit(":", 1)
                            unique_hosts_for_plugin.add(host)
                            ports_for_plugin.add(int(port_str))
                        except (ValueError, IndexError):
                            unique_hosts_for_plugin.add(host_entry)
                    else:
                        unique_hosts_for_plugin.add(host_entry)

                plugin_file = Finding(
                    scan_id=scan_id,
                    plugin_id=plugin_id,
                    review_state="pending"
                )

                finding_id = plugin_file.save(conn)

                # ========== Step 6: Collect junction records for bulk insert ==========
                junction_records = []
                for host_entry_data in hosts_data:
                    # Parse (same as before)
                    host_entry, plugin_output = host_entry_data

                    # Parse host:port - host_entry contains scan_target (possibly with port)
                    if ":" in host_entry:
                        scan_target, port_str = host_entry.rsplit(":", 1)
                        try:
                            port = int(port_str)
                        except ValueError:
                            scan_target = host_entry
                            port = None
                    else:
                        scan_target = host_entry
                        port = None

                    # Get ip_address from host_metadata
                    meta_entry = host_metadata.get(scan_target)
                    if meta_entry:
                        ip_address = meta_entry.host_ip
                    else:
                        ip_address = scan_target

                    # Get host_id from map using composite key
                    composite_key = (ip_address, scan_target)
                    host_id = host_id_map.get(composite_key)
                    if host_id:
                        junction_records.append((finding_id, host_id, port, plugin_output))

                # Bulk insert junction records
                if junction_records:
                    conn.executemany(
                        """
                        INSERT OR REPLACE INTO finding_affected_hosts (
                            finding_id, host_id, port_number, plugin_output
                        ) VALUES (?, ?, ?, ?)
                        """,
                        junction_records
                    )

        elapsed = time.time() - start_time
        log_info(f"Database updated: {len(plugins)} plugins, {scan_id=} (took {elapsed:.1f}s)")

    except Exception as e:
        log_error(f"Failed to write to database: {e}")
        # Don't fail the export if database write fails

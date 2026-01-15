"""NetExec database integration for enriching Cerno finding displays.

This module provides read-only access to NetExec protocol databases (smb.db, ssh.db, etc.)
to display relevant credentials, host access, shares, and security flags alongside
Nessus finding data.

NetExec databases are located in ~/.nxc/workspaces/<workspace>/ by default.
Each protocol has its own SQLite database (smb.db, ssh.db, ldap.db, etc.).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    pass

# Supported protocol databases
SUPPORTED_PROTOCOLS = ["smb", "ssh", "ldap", "mssql", "rdp", "winrm", "ftp", "nfs", "vnc", "wmi"]


@dataclass
class NxcCredential:
    """Credential discovered via NetExec.

    Attributes:
        protocol: Protocol where credential was found (smb, ssh, etc.)
        username: Username
        domain: Domain (for AD credentials)
        credential_type: Type of credential (plaintext, hash, key, etc.)
        has_admin: Whether this credential grants admin access
    """

    protocol: str
    username: str
    domain: Optional[str] = None
    credential_type: str = "plaintext"
    has_admin: bool = False


@dataclass
class NxcShare:
    """SMB share information.

    Attributes:
        name: Share name (e.g., C$, ADMIN$, Public)
        read_access: Whether read access was confirmed
        write_access: Whether write access was confirmed
    """

    name: str
    read_access: bool = False
    write_access: bool = False


@dataclass
class NxcSecurityFlags:
    """SMB security configuration flags.

    Attributes:
        signing_required: Whether SMB signing is required
        smbv1_enabled: Whether SMBv1 is enabled
        zerologon_vulnerable: Whether host is vulnerable to Zerologon
        petitpotam_vulnerable: Whether host is vulnerable to PetitPotam
    """

    signing_required: bool = True
    smbv1_enabled: bool = False
    zerologon_vulnerable: bool = False
    petitpotam_vulnerable: bool = False


@dataclass
class NxcHostData:
    """Aggregated NetExec data for a single host.

    Attributes:
        host_address: IP address of the host
        hostname: Hostname if known
        protocols_seen: List of protocols where this host was found
        credentials: List of credentials that work on this host
        shares: List of accessible shares (SMB only)
        security_flags: Security configuration flags (SMB only)
    """

    host_address: str
    hostname: Optional[str] = None
    protocols_seen: List[str] = field(default_factory=list)
    credentials: List[NxcCredential] = field(default_factory=list)
    shares: List[NxcShare] = field(default_factory=list)
    security_flags: Optional[NxcSecurityFlags] = None


@dataclass
class NxcEnrichmentSummary:
    """Summary of NetExec enrichment data across multiple hosts.

    Used for the summary panel display.

    Attributes:
        total_hosts_queried: Number of hosts from the finding
        hosts_with_data: Number of hosts with NetExec data
        protocols_seen: Unique protocols across all hosts
        unique_credentials: Deduplicated credentials with host counts
        shares_summary: Share access summary (name -> (read_count, write_count))
        security_flag_counts: Counts of security issues (e.g., "signing_disabled": 4)
        per_host_data: Full per-host data for detailed view
    """

    total_hosts_queried: int
    hosts_with_data: int
    protocols_seen: List[str] = field(default_factory=list)
    unique_credentials: List[tuple[NxcCredential, int]] = field(default_factory=list)  # (cred, host_count)
    shares_summary: Dict[str, tuple[int, int]] = field(default_factory=dict)  # name -> (read_count, write_count)
    security_flag_counts: Dict[str, int] = field(default_factory=dict)  # flag_name -> count
    per_host_data: Dict[str, NxcHostData] = field(default_factory=dict)  # ip -> data


class NxcDatabaseManager:
    """Manager for NetExec database queries.

    Provides read-only access to NetExec protocol databases for enriching
    Cerno finding displays with credential, access, and security data.

    Attributes:
        workspace_path: Path to NetExec workspace directory
    """

    def __init__(self, workspace_path: Path) -> None:
        """Initialize the manager.

        Args:
            workspace_path: Path to NetExec workspace directory
                           (e.g., ~/.nxc/workspaces/default/)
        """
        self.workspace_path = workspace_path
        self._connection_cache: Dict[str, sqlite3.Connection] = {}

    def is_available(self) -> bool:
        """Check if NetExec databases exist and are readable.

        Returns:
            True if at least one protocol database exists
        """
        if not self.workspace_path.exists():
            return False

        for protocol in SUPPORTED_PROTOCOLS:
            db_path = self.workspace_path / f"{protocol}.db"
            if db_path.exists():
                return True

        return False

    def get_available_protocols(self) -> List[str]:
        """Get list of protocols with existing databases.

        Returns:
            List of protocol names (e.g., ["smb", "ssh"])
        """
        available = []
        for protocol in SUPPORTED_PROTOCOLS:
            db_path = self.workspace_path / f"{protocol}.db"
            if db_path.exists():
                available.append(protocol)
        return available

    def _get_connection(self, protocol: str) -> Optional[sqlite3.Connection]:
        """Get a cached read-only connection to a protocol database.

        Args:
            protocol: Protocol name (e.g., "smb")

        Returns:
            SQLite connection or None if database doesn't exist
        """
        if protocol in self._connection_cache:
            return self._connection_cache[protocol]

        db_path = self.workspace_path / f"{protocol}.db"
        if not db_path.exists():
            return None

        try:
            # Open in read-only mode using URI
            uri = f"file:{db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=1.0)
            conn.row_factory = sqlite3.Row
            self._connection_cache[protocol] = conn
            return conn
        except sqlite3.Error:
            return None

    def close(self) -> None:
        """Close all cached database connections."""
        for conn in self._connection_cache.values():
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._connection_cache.clear()

    def _query_smb_host(self, conn: sqlite3.Connection, host_ip: str) -> Optional[NxcHostData]:
        """Query SMB database for host data.

        Args:
            conn: Database connection
            host_ip: IP address to query

        Returns:
            NxcHostData or None if host not found
        """
        try:
            # Get host record with security flags
            cursor = conn.execute(
                """
                SELECT id, ip, hostname, domain, os, smbv1, signing, zerologon, petitpotam
                FROM hosts
                WHERE ip = ?
                """,
                (host_ip,),
            )
            host_row = cursor.fetchone()
            if not host_row:
                return None

            host_id = host_row["id"]
            hostname = host_row["hostname"]

            # Build security flags
            security_flags = NxcSecurityFlags(
                signing_required=bool(host_row["signing"]) if host_row["signing"] is not None else True,
                smbv1_enabled=bool(host_row["smbv1"]) if host_row["smbv1"] is not None else False,
                zerologon_vulnerable=bool(host_row["zerologon"]) if host_row["zerologon"] is not None else False,
                petitpotam_vulnerable=bool(host_row["petitpotam"]) if host_row["petitpotam"] is not None else False,
            )

            # Get credentials with admin access
            credentials = []
            cursor = conn.execute(
                """
                SELECT u.username, u.domain, u.credtype,
                       CASE WHEN ar.id IS NOT NULL THEN 1 ELSE 0 END as has_admin
                FROM users u
                LEFT JOIN admin_relations ar ON ar.userid = u.id AND ar.hostid = ?
                LEFT JOIN loggedin_relations lr ON lr.userid = u.id AND lr.hostid = ?
                WHERE ar.id IS NOT NULL OR lr.id IS NOT NULL
                """,
                (host_id, host_id),
            )
            for row in cursor:
                credentials.append(
                    NxcCredential(
                        protocol="smb",
                        username=row["username"],
                        domain=row["domain"],
                        credential_type=row["credtype"] or "plaintext",
                        has_admin=bool(row["has_admin"]),
                    )
                )

            # Get shares
            shares = []
            cursor = conn.execute(
                """
                SELECT name, read, write
                FROM shares
                WHERE hostid = ?
                """,
                (host_id,),
            )
            for row in cursor:
                shares.append(
                    NxcShare(
                        name=row["name"],
                        read_access=bool(row["read"]),
                        write_access=bool(row["write"]),
                    )
                )

            return NxcHostData(
                host_address=host_ip,
                hostname=hostname,
                protocols_seen=["smb"],
                credentials=credentials,
                shares=shares,
                security_flags=security_flags,
            )

        except sqlite3.Error:
            return None

    def _query_ssh_host(self, conn: sqlite3.Connection, host_ip: str) -> Optional[NxcHostData]:
        """Query SSH database for host data.

        Args:
            conn: Database connection
            host_ip: IP address to query

        Returns:
            NxcHostData or None if host not found
        """
        try:
            # SSH uses 'host' column instead of 'ip'
            cursor = conn.execute(
                """
                SELECT id, host, hostname
                FROM hosts
                WHERE host = ?
                """,
                (host_ip,),
            )
            host_row = cursor.fetchone()
            if not host_row:
                return None

            host_id = host_row["id"]
            # SSH may not have hostname column in all versions
            hostname = host_row["hostname"] if "hostname" in host_row.keys() else None

            # Get credentials
            credentials = []
            cursor = conn.execute(
                """
                SELECT c.username, c.credtype,
                       CASE WHEN ar.id IS NOT NULL THEN 1 ELSE 0 END as has_admin
                FROM credentials c
                LEFT JOIN admin_relations ar ON ar.credid = c.id AND ar.hostid = ?
                LEFT JOIN loggedin_relations lr ON lr.credid = c.id AND lr.hostid = ?
                WHERE ar.id IS NOT NULL OR lr.id IS NOT NULL
                """,
                (host_id, host_id),
            )
            for row in cursor:
                credentials.append(
                    NxcCredential(
                        protocol="ssh",
                        username=row["username"],
                        domain=None,
                        credential_type=row["credtype"] or "plaintext",
                        has_admin=bool(row["has_admin"]),
                    )
                )

            if not credentials:
                return None

            return NxcHostData(
                host_address=host_ip,
                hostname=hostname,
                protocols_seen=["ssh"],
                credentials=credentials,
                shares=[],
                security_flags=None,
            )

        except sqlite3.Error:
            return None

    def _query_generic_host(
        self, conn: sqlite3.Connection, host_ip: str, protocol: str
    ) -> Optional[NxcHostData]:
        """Query a generic protocol database for host data.

        Works for protocols with standard schema (ldap, mssql, winrm, rdp, etc.)

        Args:
            conn: Database connection
            host_ip: IP address to query
            protocol: Protocol name

        Returns:
            NxcHostData or None if host not found
        """
        try:
            # Try 'ip' column first, then 'host'
            cursor = conn.execute(
                """
                SELECT id, COALESCE(ip, host) as ip, hostname
                FROM hosts
                WHERE ip = ? OR host = ?
                """,
                (host_ip, host_ip),
            )
            host_row = cursor.fetchone()
            if not host_row:
                return None

            host_id = host_row["id"]
            hostname = host_row["hostname"] if "hostname" in host_row.keys() else None

            # Try to get credentials - different protocols use different schemas
            credentials = []

            # Try users table (ldap, mssql, winrm)
            try:
                cursor = conn.execute(
                    """
                    SELECT u.username, u.domain, u.credtype,
                           CASE WHEN ar.id IS NOT NULL THEN 1 ELSE 0 END as has_admin
                    FROM users u
                    LEFT JOIN admin_relations ar ON ar.userid = u.id AND ar.hostid = ?
                    LEFT JOIN loggedin_relations lr ON lr.userid = u.id AND lr.hostid = ?
                    WHERE ar.id IS NOT NULL OR lr.id IS NOT NULL
                    """,
                    (host_id, host_id),
                )
                for row in cursor:
                    credentials.append(
                        NxcCredential(
                            protocol=protocol,
                            username=row["username"],
                            domain=row["domain"] if "domain" in row.keys() else None,
                            credential_type=row["credtype"] or "plaintext" if "credtype" in row.keys() else "plaintext",
                            has_admin=bool(row["has_admin"]),
                        )
                    )
            except sqlite3.Error:
                pass

            # Try credentials table (ftp, nfs, vnc, wmi)
            if not credentials:
                try:
                    cursor = conn.execute(
                        """
                        SELECT c.username
                        FROM credentials c
                        JOIN loggedin_relations lr ON lr.credid = c.id OR lr.cred_id = c.id
                        WHERE lr.hostid = ? OR lr.host_id = ?
                        """,
                        (host_id, host_id),
                    )
                    for row in cursor:
                        credentials.append(
                            NxcCredential(
                                protocol=protocol,
                                username=row["username"],
                                domain=None,
                                credential_type="plaintext",
                                has_admin=False,
                            )
                        )
                except sqlite3.Error:
                    pass

            if not credentials:
                return None

            return NxcHostData(
                host_address=host_ip,
                hostname=hostname,
                protocols_seen=[protocol],
                credentials=credentials,
                shares=[],
                security_flags=None,
            )

        except sqlite3.Error:
            return None

    def get_host_enrichment(self, host_ip: str) -> Optional[NxcHostData]:
        """Get aggregated NetExec data for a single host.

        Queries all available protocol databases and merges results.

        Args:
            host_ip: IP address to query

        Returns:
            NxcHostData with merged data from all protocols, or None if no data
        """
        merged_data: Optional[NxcHostData] = None

        for protocol in self.get_available_protocols():
            conn = self._get_connection(protocol)
            if not conn:
                continue

            # Query based on protocol
            if protocol == "smb":
                data = self._query_smb_host(conn, host_ip)
            elif protocol == "ssh":
                data = self._query_ssh_host(conn, host_ip)
            else:
                data = self._query_generic_host(conn, host_ip, protocol)

            if data:
                if merged_data is None:
                    merged_data = data
                else:
                    # Merge protocols, credentials, shares
                    merged_data.protocols_seen.extend(data.protocols_seen)
                    merged_data.credentials.extend(data.credentials)
                    merged_data.shares.extend(data.shares)
                    if data.security_flags and not merged_data.security_flags:
                        merged_data.security_flags = data.security_flags
                    if data.hostname and not merged_data.hostname:
                        merged_data.hostname = data.hostname

        return merged_data

    def get_hosts_enrichment(self, host_ips: List[str]) -> NxcEnrichmentSummary:
        """Get enrichment summary for multiple hosts.

        Args:
            host_ips: List of IP addresses to query

        Returns:
            NxcEnrichmentSummary with aggregated data
        """
        per_host_data: Dict[str, NxcHostData] = {}
        all_protocols: set[str] = set()
        credential_counts: Dict[tuple[str, str, Optional[str], str], int] = {}  # (proto, user, domain, type) -> count
        shares_summary: Dict[str, tuple[int, int]] = {}  # name -> (read_count, write_count)
        security_flag_counts: Dict[str, int] = {
            "signing_disabled": 0,
            "smbv1_enabled": 0,
            "zerologon": 0,
            "petitpotam": 0,
        }

        for host_ip in host_ips:
            data = self.get_host_enrichment(host_ip)
            if data:
                per_host_data[host_ip] = data
                all_protocols.update(data.protocols_seen)

                # Count credentials
                for cred in data.credentials:
                    key = (cred.protocol, cred.username, cred.domain, cred.credential_type)
                    credential_counts[key] = credential_counts.get(key, 0) + 1

                # Aggregate shares
                for share in data.shares:
                    read_count, write_count = shares_summary.get(share.name, (0, 0))
                    if share.read_access:
                        read_count += 1
                    if share.write_access:
                        write_count += 1
                    shares_summary[share.name] = (read_count, write_count)

                # Count security flags
                if data.security_flags:
                    if not data.security_flags.signing_required:
                        security_flag_counts["signing_disabled"] += 1
                    if data.security_flags.smbv1_enabled:
                        security_flag_counts["smbv1_enabled"] += 1
                    if data.security_flags.zerologon_vulnerable:
                        security_flag_counts["zerologon"] += 1
                    if data.security_flags.petitpotam_vulnerable:
                        security_flag_counts["petitpotam"] += 1

        # Build unique credentials with counts
        unique_credentials: List[tuple[NxcCredential, int]] = []
        for (proto, user, domain, cred_type), count in credential_counts.items():
            # Determine if any instance has admin
            has_admin = any(
                cred.has_admin
                for data in per_host_data.values()
                for cred in data.credentials
                if cred.protocol == proto and cred.username == user and cred.domain == domain
            )
            unique_credentials.append(
                (
                    NxcCredential(
                        protocol=proto,
                        username=user,
                        domain=domain,
                        credential_type=cred_type,
                        has_admin=has_admin,
                    ),
                    count,
                )
            )

        # Sort by host count descending
        unique_credentials.sort(key=lambda x: x[1], reverse=True)

        # Remove zero counts from security flags
        security_flag_counts = {k: v for k, v in security_flag_counts.items() if v > 0}

        return NxcEnrichmentSummary(
            total_hosts_queried=len(host_ips),
            hosts_with_data=len(per_host_data),
            protocols_seen=sorted(all_protocols),
            unique_credentials=unique_credentials,
            shares_summary=shares_summary,
            security_flag_counts=security_flag_counts,
            per_host_data=per_host_data,
        )


# Module-level singleton for reuse
_nxc_manager: Optional[NxcDatabaseManager] = None


def get_nxc_manager() -> Optional[NxcDatabaseManager]:
    """Get the NetExec database manager singleton.

    Lazily initializes the manager based on configuration.
    Returns None if NetExec integration is disabled or unavailable.

    Returns:
        NxcDatabaseManager or None
    """
    global _nxc_manager

    if _nxc_manager is not None:
        return _nxc_manager

    # Import config lazily to avoid circular imports
    from .config import load_config

    config = load_config()

    # Check if disabled
    if not getattr(config, "nxc_enrichment_enabled", True):
        return None

    # Get workspace path
    workspace_path_str = getattr(config, "nxc_workspace_path", None)
    if workspace_path_str == "":
        # Explicitly disabled
        return None

    if workspace_path_str:
        workspace_path = Path(workspace_path_str).expanduser()
    else:
        # Default path
        workspace_path = Path.home() / ".nxc" / "workspaces" / "default"

    if not workspace_path.exists():
        return None

    _nxc_manager = NxcDatabaseManager(workspace_path)
    if not _nxc_manager.is_available():
        _nxc_manager = None
        return None

    return _nxc_manager


def reset_nxc_manager() -> None:
    """Reset the singleton manager (useful for testing)."""
    global _nxc_manager
    if _nxc_manager:
        _nxc_manager.close()
    _nxc_manager = None

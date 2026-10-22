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
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .logging_setup import log_debug

# Supported protocol databases
SUPPORTED_PROTOCOLS = [
    "smb",
    "ssh",
    "ldap",
    "mssql",
    "rdp",
    "winrm",
    "ftp",
    "nfs",
    "vnc",
    "wmi",
]


@dataclass(frozen=True)
class _ProtocolSpec:
    """How one NetExec protocol database is laid out.

    Derived from the schemas NetExec 1.5.1 creates (see ``tests/fixtures/nxc``).
    Every table/column name used in dynamically built SQL comes from these
    specs, never from user input; optional columns are additionally checked
    against ``PRAGMA table_info`` so schema drift degrades instead of failing.

    Attributes:
        address_col: ``hosts`` column holding the target address (``ip`` or ``host``)
        host_attrs: ``hosts`` columns surfaced in ``NxcHostData.protocol_details``
        cred_table: Credential table (``users`` or ``credentials``), or None
        rel_cred_col: Credential FK column in ``admin_relations``/``loggedin_relations``
        rel_host_col: Host FK column in ``admin_relations``/``loggedin_relations``
    """

    address_col: str
    host_attrs: Tuple[str, ...]
    cred_table: Optional[str] = None
    rel_cred_col: str = "userid"
    rel_host_col: str = "hostid"


# Relations tables are optional per protocol: ldap has `users` but no relations,
# vnc/wmi have `credentials` but no relations, rdp has neither. Missing tables
# are detected at query time and simply skipped.
_PROTOCOL_SPECS: Dict[str, _ProtocolSpec] = {
    "smb": _ProtocolSpec(
        "ip",
        (
            "hostname",
            "domain",
            "os",
            "dc",
            "smbv1",
            "signing",
            "spooler",
            "zerologon",
            "petitpotam",
        ),
        "users",
    ),
    "mssql": _ProtocolSpec("ip", ("hostname", "domain", "os", "instances"), "users"),
    "winrm": _ProtocolSpec("ip", ("port", "hostname", "domain", "os"), "users"),
    "ldap": _ProtocolSpec(
        "ip",
        ("hostname", "domain", "os", "signing_required", "channel_binding"),
        "users",
    ),
    "ssh": _ProtocolSpec(
        "host", ("port", "banner", "os"), "credentials", "credid", "hostid"
    ),
    "ftp": _ProtocolSpec("host", ("port", "banner"), "credentials", "credid", "hostid"),
    "nfs": _ProtocolSpec(
        "ip", ("hostname", "port"), "credentials", "cred_id", "host_id"
    ),
    "rdp": _ProtocolSpec("ip", ("port", "hostname", "domain", "os", "nla")),
    "vnc": _ProtocolSpec("ip", ("hostname", "port", "server_banner"), "credentials"),
    "wmi": _ProtocolSpec("ip", ("hostname", "port"), "credentials"),
}

# hosts columns declared BOOLEAN by NetExec; normalised to Python bools.
_BOOLEAN_ATTRS = frozenset(
    {
        "dc",
        "smbv1",
        "signing",
        "spooler",
        "zerologon",
        "petitpotam",
        "signing_required",
        "nla",
    }
)


@dataclass
class NxcCredential:
    """Credential discovered via NetExec.

    Attributes:
        protocol: Protocol where credential was found (smb, ssh, etc.)
        username: Username
        domain: Domain (for AD credentials)
        credential_type: Type of credential (plaintext, hash, key, etc.)
        has_admin: Whether this credential grants admin access
        pillaged: Whether this credential was dumped from this host
            (``users.pillaged_from_hostid``) rather than proven to log in to it
    """

    protocol: str
    username: str
    domain: Optional[str] = None
    credential_type: str = "plaintext"
    has_admin: bool = False
    pillaged: bool = False


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
class NxcConfCheck:
    """A failed SMB configuration check (NetExec ``conf_checks_results``).

    Attributes:
        name: Check name (e.g., "LDAP signing")
        reasons: NetExec's explanation of why the check failed
    """

    name: str
    reasons: Optional[str] = None


@dataclass
class NxcHostData:
    """Aggregated NetExec data for a single host.

    Attributes:
        host_address: IP address of the host
        hostname: Hostname if known
        protocols_seen: List of protocols where this host was found
        credentials: List of credentials that work on (or were dumped from) this host
        shares: List of accessible shares (SMB only)
        security_flags: Security configuration flags (SMB only)
        protocol_details: Per-protocol host attributes, e.g.
            ``{"rdp": {"ports": [3389], "nla": False}, "ssh": {"ports": [22], "banner": "..."}}``
        failed_checks: Failed SMB configuration checks
    """

    host_address: str
    hostname: Optional[str] = None
    protocols_seen: List[str] = field(default_factory=list)
    credentials: List[NxcCredential] = field(default_factory=list)
    shares: List[NxcShare] = field(default_factory=list)
    security_flags: Optional[NxcSecurityFlags] = None
    protocol_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    failed_checks: List[NxcConfCheck] = field(default_factory=list)


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
    unique_credentials: List[tuple[NxcCredential, int]] = field(
        default_factory=list
    )  # (cred, host_count)
    shares_summary: Dict[str, tuple[int, int]] = field(
        default_factory=dict
    )  # name -> (read_count, write_count)
    security_flag_counts: Dict[str, int] = field(
        default_factory=dict
    )  # flag_name -> count
    per_host_data: Dict[str, NxcHostData] = field(default_factory=dict)  # ip -> data


@dataclass(frozen=True)
class NxcCredentialRef:
    """A non-secret reference to a credential stored in the NetExec workspace.

    The actual password/hash value is NEVER included here; only ``secret_kind``
    says whether a usable secret exists. The opaque ``ref`` (``"<protocol>:<id>"``)
    is passed back to :meth:`NxcDatabaseManager.resolve_credential_secret` to
    obtain the secret server-side, at execution time only.
    """

    ref: str
    protocol: str
    username: str
    domain: Optional[str] = None
    credential_type: Optional[str] = None
    secret_kind: Optional[str] = None  # 'password' | 'hash' | None (no usable secret)


@dataclass(frozen=True)
class ResolvedSecret:
    """A resolved credential secret. Handle server-side only; never log or return."""

    username: str
    domain: Optional[str]
    secret_kind: str  # 'password' | 'hash'
    secret_value: str


def _classify_secret_kind(
    credtype: Optional[str], password: Optional[str]
) -> Optional[str]:
    """Derive secret_kind from a nxc credtype + stored password/hash value."""
    if not password:
        return None
    return "hash" if (credtype or "").strip().lower() == "hash" else "password"


def _placeholders(n: int) -> str:
    """Return ``?, ?, ...`` with ``n`` bound-parameter markers."""
    return ", ".join("?" * n)


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
        self._columns_cache: Dict[Tuple[str, str], FrozenSet[str]] = {}

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
        self._columns_cache.clear()

    def _columns(
        self, protocol: str, conn: sqlite3.Connection, table: str
    ) -> FrozenSet[str]:
        """Return the column names of ``table`` (empty if the table is missing).

        Args:
            protocol: Protocol name (cache key)
            conn: Connection to that protocol's database
            table: Table name (always a constant from ``_PROTOCOL_SPECS``)

        Returns:
            Frozen set of column names
        """
        key = (protocol, table)
        if key not in self._columns_cache:
            rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            self._columns_cache[key] = frozenset(row[1] for row in rows)
        return self._columns_cache[key]

    def _query_protocol_host(
        self, conn: sqlite3.Connection, host_ip: str, protocol: str
    ) -> Optional[NxcHostData]:
        """Query one protocol database for a host.

        Host presence alone is returned (with ``protocol_details``) even when no
        credentials are tied to the host, so every protocol NetExec touched shows up.

        Args:
            conn: Database connection
            host_ip: IP address to query
            protocol: Protocol name (key of ``_PROTOCOL_SPECS``)

        Returns:
            NxcHostData or None if the host is not in this database
        """
        spec = _PROTOCOL_SPECS.get(protocol)
        if spec is None:
            return None

        try:
            host_cols = self._columns(protocol, conn, "hosts")
            if spec.address_col not in host_cols:
                log_debug(
                    f"nxc {protocol}.db: hosts.{spec.address_col} missing; skipping"
                )
                return None
            attrs = [a for a in spec.host_attrs if a in host_cols]
            select_cols = ", ".join(["id", *attrs])
            # Non-UNIQUE address columns (ssh/ftp/nfs/vnc/wmi) hold one row per port.
            rows = conn.execute(
                f"SELECT {select_cols} FROM hosts WHERE {spec.address_col} = ? ORDER BY id",
                (host_ip,),
            ).fetchall()
            if not rows:
                return None

            host_ids = [row["id"] for row in rows]
            details = self._host_details(rows, attrs)
            hostname = details.pop("hostname", None)

            data = NxcHostData(
                host_address=host_ip,
                hostname=hostname,
                protocols_seen=[protocol],
                credentials=self._host_credentials(conn, protocol, spec, host_ids),
                protocol_details={protocol: details},
            )
            if protocol == "smb":
                self._add_smb_extras(conn, data, details, host_ids)
            return data

        except sqlite3.Error as exc:
            log_debug(f"nxc {protocol}.db query failed for {host_ip}: {exc}")
            return None

    @staticmethod
    def _host_details(rows: List[sqlite3.Row], attrs: List[str]) -> Dict[str, Any]:
        """Collapse host rows into one attribute dict.

        ``port`` becomes a sorted ``ports`` list; other attributes take the first
        non-NULL value. BOOLEAN columns are normalised to bool.
        """
        details: Dict[str, Any] = {}
        for attr in attrs:
            values = [row[attr] for row in rows if row[attr] is not None]
            if not values:
                continue
            if attr == "port":
                details["ports"] = sorted(set(values))
            elif attr in _BOOLEAN_ATTRS:
                details[attr] = bool(values[0])
            else:
                details[attr] = values[0]
        return details

    def _host_credentials(
        self,
        conn: sqlite3.Connection,
        protocol: str,
        spec: _ProtocolSpec,
        host_ids: List[int],
    ) -> List[NxcCredential]:
        """Credentials tied to the host via admin/loggedin relations or pillaging.

        Uses EXISTS rather than joins so a credential appears once no matter how
        many (non-unique) relation rows NetExec recorded.
        """
        table = spec.cred_table
        if table is None:
            return []
        cred_cols = self._columns(protocol, conn, table)
        if "username" not in cred_cols:
            return []

        in_ids = _placeholders(len(host_ids))

        def rel_exists(rel_table: str) -> Optional[str]:
            if {spec.rel_cred_col, spec.rel_host_col} <= self._columns(
                protocol, conn, rel_table
            ):
                return (
                    f"EXISTS (SELECT 1 FROM {rel_table} r WHERE r.{spec.rel_cred_col} = c.id "
                    f"AND r.{spec.rel_host_col} IN ({in_ids}))"
                )
            return None

        admin_expr = rel_exists("admin_relations")
        conditions = [e for e in (admin_expr, rel_exists("loggedin_relations")) if e]
        pillaged_expr: Optional[str] = None
        if "pillaged_from_hostid" in cred_cols:
            pillaged_expr = f"c.pillaged_from_hostid IN ({in_ids})"
            conditions.append(pillaged_expr)
        if not conditions:
            return []

        domain_expr = "c.domain" if "domain" in cred_cols else "NULL"
        credtype_expr = "c.credtype" if "credtype" in cred_cols else "NULL"
        sql = (
            f"SELECT c.username, {domain_expr} AS domain, {credtype_expr} AS credtype, "
            f"{admin_expr or '0'} AS has_admin, {pillaged_expr or '0'} AS pillaged "
            f"FROM {table} c WHERE {' OR '.join(conditions)} ORDER BY c.id"
        )
        # Parameter order follows placeholder order: SELECT exprs, then WHERE conditions.
        n_select = sum(1 for e in (admin_expr, pillaged_expr) if e)
        params = host_ids * (n_select + len(conditions))

        return [
            NxcCredential(
                protocol=protocol,
                username=row["username"],
                domain=row["domain"],
                credential_type=row["credtype"] or "plaintext",
                has_admin=bool(row["has_admin"]),
                pillaged=bool(row["pillaged"]),
            )
            for row in conn.execute(sql, params)
        ]

    def _add_smb_extras(
        self,
        conn: sqlite3.Connection,
        data: NxcHostData,
        details: Dict[str, Any],
        host_ids: List[int],
    ) -> None:
        """Attach SMB-only data: security flags, shares, failed config checks."""
        data.security_flags = NxcSecurityFlags(
            signing_required=details.get("signing", True),
            smbv1_enabled=details.get("smbv1", False),
            zerologon_vulnerable=details.get("zerologon", False),
            petitpotam_vulnerable=details.get("petitpotam", False),
        )
        in_ids = _placeholders(len(host_ids))

        # shares is UNIQUE(hostid, userid, name): one row per user — collapse per name.
        if {"hostid", "name", "read", "write"} <= self._columns("smb", conn, "shares"):
            for row in conn.execute(
                f"SELECT name, MAX(read) AS r, MAX(write) AS w FROM shares "
                f"WHERE hostid IN ({in_ids}) GROUP BY name ORDER BY MIN(id)",
                host_ids,
            ):
                data.shares.append(
                    NxcShare(
                        name=row["name"],
                        read_access=bool(row["r"]),
                        write_access=bool(row["w"]),
                    )
                )

        if {"host_id", "check_id", "secure"} <= self._columns(
            "smb", conn, "conf_checks_results"
        ) and "name" in self._columns("smb", conn, "conf_checks"):
            for row in conn.execute(
                f"SELECT c.name, r.reasons FROM conf_checks_results r "
                f"JOIN conf_checks c ON c.id = r.check_id "
                f"WHERE r.host_id IN ({in_ids}) AND r.secure = 0 ORDER BY r.id",
                host_ids,
            ):
                data.failed_checks.append(
                    NxcConfCheck(name=row["name"], reasons=row["reasons"] or None)
                )

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

            data = self._query_protocol_host(conn, host_ip, protocol)
            if not data:
                continue
            if merged_data is None:
                merged_data = data
                continue

            merged_data.protocols_seen.extend(data.protocols_seen)
            merged_data.credentials.extend(data.credentials)
            merged_data.shares.extend(data.shares)
            merged_data.protocol_details.update(data.protocol_details)
            merged_data.failed_checks.extend(data.failed_checks)
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
        credential_counts: Dict[tuple[str, str, Optional[str], str], int] = (
            {}
        )  # (proto, user, domain, type) -> count
        shares_summary: Dict[str, tuple[int, int]] = (
            {}
        )  # name -> (read_count, write_count)
        security_flag_counts: Dict[str, int] = {
            "signing_disabled": 0,
            "smbv1_enabled": 0,
            "zerologon": 0,
            "petitpotam": 0,
            "ldap_signing_disabled": 0,
            "rdp_nla_disabled": 0,
        }

        for host_ip in host_ips:
            data = self.get_host_enrichment(host_ip)
            if data:
                per_host_data[host_ip] = data
                all_protocols.update(data.protocols_seen)

                # Count credentials
                for cred in data.credentials:
                    key = (
                        cred.protocol,
                        cred.username,
                        cred.domain,
                        cred.credential_type,
                    )
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
                # Only explicit False counts; NULL (not checked) is absent from details.
                if (
                    data.protocol_details.get("ldap", {}).get("signing_required")
                    is False
                ):
                    security_flag_counts["ldap_signing_disabled"] += 1
                if data.protocol_details.get("rdp", {}).get("nla") is False:
                    security_flag_counts["rdp_nla_disabled"] += 1

        # Build unique credentials with counts
        unique_credentials: List[tuple[NxcCredential, int]] = []
        for (proto, user, domain, cred_type), count in credential_counts.items():
            # Determine if any instance has admin / was pillaged
            instances = [
                cred
                for data in per_host_data.values()
                for cred in data.credentials
                if cred.protocol == proto
                and cred.username == user
                and cred.domain == domain
            ]
            has_admin = any(cred.has_admin for cred in instances)
            pillaged = any(cred.pillaged for cred in instances)
            unique_credentials.append(
                (
                    NxcCredential(
                        protocol=proto,
                        username=user,
                        domain=domain,
                        credential_type=cred_type,
                        has_admin=has_admin,
                        pillaged=pillaged,
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

    def list_credential_refs(self) -> List[NxcCredentialRef]:
        """List non-secret references to every stored credential in the workspace.

        Reads each protocol's credential table (``users``/``credentials``) for its
        rowid, username, domain and credtype — never the password/hash value. The
        rowid-based ``ref`` is stable within the workspace and is what
        :meth:`resolve_credential_secret` consumes.
        """
        refs: List[NxcCredentialRef] = []
        for protocol, spec in _PROTOCOL_SPECS.items():
            if not spec.cred_table:
                continue
            conn = self._get_connection(protocol)
            if conn is None:
                continue
            cols = self._columns(protocol, conn, spec.cred_table)
            if "username" not in cols:
                continue
            select_domain = "domain" in cols
            select_credtype = "credtype" in cols
            fields = ["id", "username", "password"]
            if select_domain:
                fields.append("domain")
            if select_credtype:
                fields.append("credtype")
            try:
                rows = conn.execute(
                    f'SELECT {", ".join(fields)} FROM "{spec.cred_table}" ORDER BY id'
                ).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                username = row["username"]
                if not username:
                    continue
                credtype = row["credtype"] if select_credtype else None
                refs.append(
                    NxcCredentialRef(
                        ref=f"{protocol}:{row['id']}",
                        protocol=protocol,
                        username=username,
                        domain=row["domain"] if select_domain else None,
                        credential_type=credtype,
                        secret_kind=_classify_secret_kind(credtype, row["password"]),
                    )
                )
        return refs

    def resolve_credential_secret(self, ref: str) -> Optional[ResolvedSecret]:
        """Resolve a credential ``ref`` to its real secret (server-side use only).

        Returns None if the ref is malformed, the protocol/row is gone, or the
        credential has no usable secret. The returned value must never be logged,
        returned to a client, or written to an artifact.
        """
        try:
            protocol, rowid_str = ref.split(":", 1)
            rowid = int(rowid_str)
        except (ValueError, AttributeError):
            return None
        spec = _PROTOCOL_SPECS.get(protocol)
        if spec is None or not spec.cred_table:
            return None
        conn = self._get_connection(protocol)
        if conn is None:
            return None
        cols = self._columns(protocol, conn, spec.cred_table)
        if "username" not in cols or "password" not in cols:
            return None
        select_domain = "domain" in cols
        select_credtype = "credtype" in cols
        fields = ["username", "password"]
        if select_domain:
            fields.append("domain")
        if select_credtype:
            fields.append("credtype")
        try:
            row = conn.execute(
                f'SELECT {", ".join(fields)} FROM "{spec.cred_table}" WHERE id = ?',
                (rowid,),
            ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        password = row["password"]
        credtype = row["credtype"] if select_credtype else None
        kind = _classify_secret_kind(credtype, password)
        if kind is None:
            return None
        return ResolvedSecret(
            username=row["username"],
            domain=row["domain"] if select_domain else None,
            secret_kind=kind,
            secret_value=password,
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


def list_credential_refs() -> List[NxcCredentialRef]:
    """List non-secret credential references from the NetExec workspace (or [])."""
    manager = get_nxc_manager()
    if manager is None:
        return []
    return manager.list_credential_refs()


def resolve_credential_secret(ref: str) -> Optional[ResolvedSecret]:
    """Resolve a credential ``ref`` to its secret server-side (or None)."""
    manager = get_nxc_manager()
    if manager is None:
        return None
    return manager.resolve_credential_secret(ref)

"""SQLite database connection and management for cerno.

This module provides SQLite connection management, schema initialization,
and transaction helpers for tracking findings, review state, tool executions,
and artifacts.

Database location: ~/.cerno/cerno.db (global, cross-scan queries)
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional, cast

from .logging_setup import log_error, log_info


# ========== Database Configuration ==========

def get_database_path() -> Path:
    """Get path to cerno database file.

    Returns:
        Path to ~/.cerno/cerno.db
    """
    db_dir = Path.home() / ".cerno"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "cerno.db"


DATABASE_PATH = get_database_path()
"""Global database path for all scans."""


# ========== Schema ==========

SCHEMA_VERSION = 1
"""Schema version.

Note: Database is created directly in normalized structure.
Future versions may implement migrations, but current approach is
to create the final schema on initialization.

Schema features:
- Normalized host and port tables (cross-scan tracking)
- Foundation lookup tables (severity_levels, artifact_types)
- SQL views for computed statistics
- Audit logging with triggers

Note: SCHEMA_SQL has been split into SCHEMA_SQL_TABLES and SCHEMA_SQL_VIEWS
      for organization purposes.
"""

SCHEMA_SQL_TABLES = """
-- See schema.sql for full documentation
-- This creates all tables (but NOT views - those are created separately)

CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL UNIQUE,
    nessus_file_path TEXT,
    nessus_file_hash TEXT,
    export_root TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_reviewed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(scan_name);

CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,
    plugin_name TEXT NOT NULL,
    severity_int INTEGER NOT NULL,
    has_metasploit BOOLEAN DEFAULT 0,
    cvss3_score REAL,
    cvss2_score REAL,
    metasploit_names TEXT,
    cves TEXT,
    plugin_url TEXT,
    metadata_fetched_at TIMESTAMP,
    CONSTRAINT severity_range CHECK (severity_int BETWEEN 0 AND 4),
    FOREIGN KEY (severity_int) REFERENCES severity_levels(severity_int)
);

CREATE INDEX IF NOT EXISTS idx_plugins_severity ON plugins(severity_int);
CREATE INDEX IF NOT EXISTS idx_plugins_metasploit ON plugins(has_metasploit);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    plugin_id INTEGER NOT NULL,
    review_state TEXT DEFAULT 'pending',
    reviewed_at TIMESTAMP,
    reviewed_by TEXT,
    review_notes TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id),
    CONSTRAINT valid_review_state CHECK (review_state IN ('pending', 'reviewed', 'completed', 'skipped')),
    CONSTRAINT unique_scan_plugin UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_plugin ON findings(plugin_id);
CREATE INDEX IF NOT EXISTS idx_findings_review_state ON findings(review_state);
CREATE INDEX IF NOT EXISTS idx_findings_scan_plugin ON findings(scan_id, plugin_id);

CREATE TABLE IF NOT EXISTS finding_affected_hosts (
    fah_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    port_number INTEGER,
    plugin_output TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    FOREIGN KEY (port_number) REFERENCES ports(port_number),
    CONSTRAINT unique_finding_host_port UNIQUE (finding_id, host_id, port_number)
);

CREATE INDEX IF NOT EXISTS idx_fah_finding ON finding_affected_hosts(finding_id);
CREATE INDEX IF NOT EXISTS idx_fah_host ON finding_affected_hosts(host_id);
CREATE INDEX IF NOT EXISTS idx_fah_port ON finding_affected_hosts(port_number);

CREATE TABLE IF NOT EXISTS sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    session_start TIMESTAMP NOT NULL,
    session_end TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_scan ON sessions(scan_id);

CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    finding_id INTEGER,
    tool_name TEXT NOT NULL,
    tool_protocol TEXT,
    command_text TEXT NOT NULL,
    command_args TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_code INTEGER,
    duration_seconds REAL,
    host_count INTEGER,
    sampled BOOLEAN DEFAULT 0,
    ports TEXT,
    used_sudo BOOLEAN DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_finding ON tool_executions(finding_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER,
    artifact_path TEXT NOT NULL UNIQUE,
    artifact_type_id INTEGER,
    file_size_bytes INTEGER,
    file_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,
    metadata TEXT,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE SET NULL,
    FOREIGN KEY (artifact_type_id) REFERENCES artifact_types(artifact_type_id)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_execution ON artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type_id);

CREATE TABLE IF NOT EXISTS workflow_executions (
    workflow_execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    workflow_name TEXT NOT NULL,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT 0,
    results TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_finding ON workflow_executions(finding_id);

-- Severity levels lookup table (normalized reference data)
CREATE TABLE IF NOT EXISTS severity_levels (
    severity_int INTEGER PRIMARY KEY,
    severity_label TEXT NOT NULL,
    severity_order INTEGER NOT NULL,
    color_hint TEXT,
    CONSTRAINT unique_severity_label UNIQUE (severity_label)
);

-- Artifact types lookup table (enforces consistency)
CREATE TABLE IF NOT EXISTS artifact_types (
    artifact_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_name TEXT NOT NULL UNIQUE,
    file_extension TEXT,
    description TEXT,
    parser_module TEXT
);

-- Audit log for tracking changes to critical tables
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    action TEXT CHECK(action IN ('INSERT', 'UPDATE', 'DELETE')),
    changed_by TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    old_values TEXT,
    new_values TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_table_record ON audit_log(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_changed_at ON audit_log(changed_at);

-- Hosts table (normalized host data across scans)
-- Supports both IP-targeted and FQDN-targeted scans:
--   - ip_address: Always the resolved IP (from host-ip tag)
--   - scan_target: What was scanned (IP or FQDN from ReportHost@name)
--   - Composite unique: same IP via same target = same host
CREATE TABLE IF NOT EXISTS hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    scan_target TEXT NOT NULL,
    scan_target_type TEXT CHECK(scan_target_type IN ('ipv4', 'ipv6', 'fqdn')) NOT NULL,
    netbios_name TEXT,
    fqdn TEXT,
    reverse_dns TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, scan_target)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_hosts_target ON hosts(scan_target);
CREATE INDEX IF NOT EXISTS idx_hosts_target_type ON hosts(scan_target_type);
CREATE INDEX IF NOT EXISTS idx_hosts_netbios ON hosts(netbios_name);
CREATE INDEX IF NOT EXISTS idx_hosts_fqdn ON hosts(fqdn);

-- Ports table (port metadata)
CREATE TABLE IF NOT EXISTS ports (
    port_number INTEGER PRIMARY KEY CHECK(port_number BETWEEN 1 AND 65535),
    service_name TEXT,
    description TEXT
);
"""

SCHEMA_SQL_VIEWS = """
-- ========== VIEWS (Computed Statistics) ==========
-- These views provide computed aggregates without storing redundant data in tables

-- Finding statistics (replaces host_count, port_count columns)
CREATE VIEW IF NOT EXISTS v_finding_stats AS
SELECT
    f.finding_id,
    f.scan_id,
    f.plugin_id,
    f.review_state,
    f.reviewed_at,
    f.reviewed_by,
    f.review_notes,
    COUNT(DISTINCT fah.host_id) as host_count,
    COUNT(DISTINCT fah.port_number) as port_count
FROM findings f
LEFT JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
GROUP BY f.finding_id, f.scan_id, f.plugin_id, f.review_state,
         f.reviewed_at, f.reviewed_by, f.review_notes;

-- Session statistics (replaces aggregate columns in sessions table)
CREATE VIEW IF NOT EXISTS v_session_stats AS
SELECT
    s.session_id,
    s.scan_id,
    s.session_start,
    s.session_end,
    (julianday(s.session_end) - julianday(s.session_start)) * 86400 AS duration_seconds,
    COUNT(DISTINCT CASE WHEN f.review_state = 'reviewed' THEN f.finding_id END) as files_reviewed,
    COUNT(DISTINCT CASE WHEN f.review_state = 'completed' THEN f.finding_id END) as files_completed,
    COUNT(DISTINCT CASE WHEN f.review_state = 'skipped' THEN f.finding_id END) as files_skipped,
    COUNT(DISTINCT te.execution_id) as tools_executed,
    COUNT(DISTINCT CASE WHEN p.cves IS NOT NULL THEN p.plugin_id END) as cves_extracted
FROM sessions s
LEFT JOIN findings f ON s.scan_id = f.scan_id
    AND f.reviewed_at >= s.session_start
    AND (s.session_end IS NULL OR f.reviewed_at <= s.session_end)
LEFT JOIN tool_executions te ON s.session_id = te.session_id
LEFT JOIN plugins p ON f.plugin_id = p.plugin_id
GROUP BY s.session_id, s.scan_id, s.session_start, s.session_end;

-- Plugins with severity labels (replaces severity_label column in plugins)
CREATE VIEW IF NOT EXISTS v_plugins_with_severity AS
SELECT
    p.plugin_id,
    p.plugin_name,
    p.severity_int,
    sl.severity_label,
    sl.color_hint,
    p.has_metasploit,
    p.cvss3_score,
    p.cvss2_score,
    p.cves,
    p.metasploit_names,
    p.plugin_url,
    p.metadata_fetched_at
FROM plugins p
JOIN severity_levels sl ON p.severity_int = sl.severity_int;

-- Host findings summary (cross-scan tracking - new capability)
CREATE VIEW IF NOT EXISTS v_host_findings AS
SELECT
    h.host_id,
    h.ip_address,
    h.scan_target,
    h.scan_target_type,
    h.netbios_name,
    h.fqdn,
    h.first_seen,
    h.last_seen,
    COUNT(DISTINCT f.scan_id) as scan_count,
    COUNT(DISTINCT f.finding_id) as finding_count,
    COUNT(DISTINCT fah.port_number) as port_count,
    MAX(p.severity_int) as max_severity
FROM hosts h
LEFT JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
LEFT JOIN findings f ON fah.finding_id = f.finding_id
LEFT JOIN plugins p ON f.plugin_id = p.plugin_id
GROUP BY h.host_id, h.ip_address, h.scan_target, h.scan_target_type,
         h.netbios_name, h.fqdn, h.first_seen, h.last_seen;

-- Artifacts with type information (replaces artifact_type column)
CREATE VIEW IF NOT EXISTS v_artifacts_with_types AS
SELECT
    a.artifact_id,
    a.execution_id,
    a.artifact_path,
    at.type_name as artifact_type,
    at.file_extension,
    at.description as artifact_description,
    a.file_size_bytes,
    a.file_hash,
    a.created_at,
    a.last_accessed_at,
    a.metadata
FROM artifacts a
LEFT JOIN artifact_types at ON a.artifact_type_id = at.artifact_type_id;

-- Scan plugin summary (for cross-scan comparison)
-- Shows all plugins present in each scan with host/port counts
CREATE VIEW IF NOT EXISTS v_scan_plugin_summary AS
SELECT
    f.scan_id,
    s.scan_name,
    s.created_at as scan_date,
    f.plugin_id,
    p.plugin_name,
    p.severity_int,
    sl.severity_label,
    p.has_metasploit,
    p.cvss3_score,
    COUNT(DISTINCT fah.host_id) as affected_hosts,
    COUNT(DISTINCT fah.port_number) as affected_ports
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
JOIN plugins p ON f.plugin_id = p.plugin_id
JOIN severity_levels sl ON p.severity_int = sl.severity_int
LEFT JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
GROUP BY f.scan_id, s.scan_name, s.created_at, f.plugin_id, p.plugin_name,
         p.severity_int, sl.severity_label, p.has_metasploit, p.cvss3_score;

-- Host scan findings (for host vulnerability history)
-- Shows per-host statistics broken down by scan
-- Uses COUNT(DISTINCT) to count unique plugins per severity (not rows in junction table)
CREATE VIEW IF NOT EXISTS v_host_scan_findings AS
SELECT
    h.host_id,
    h.ip_address,
    h.scan_target,
    h.scan_target_type,
    f.scan_id,
    s.scan_name,
    s.created_at as scan_date,
    COUNT(DISTINCT f.plugin_id) as finding_count,
    MAX(p.severity_int) as max_severity,
    COUNT(DISTINCT CASE WHEN p.severity_int = 4 THEN f.plugin_id END) as critical_count,
    COUNT(DISTINCT CASE WHEN p.severity_int = 3 THEN f.plugin_id END) as high_count,
    COUNT(DISTINCT CASE WHEN p.severity_int = 2 THEN f.plugin_id END) as medium_count,
    COUNT(DISTINCT CASE WHEN p.severity_int = 1 THEN f.plugin_id END) as low_count,
    COUNT(DISTINCT CASE WHEN p.severity_int = 0 THEN f.plugin_id END) as info_count
FROM hosts h
JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
JOIN findings f ON fah.finding_id = f.finding_id
JOIN scans s ON f.scan_id = s.scan_id
JOIN plugins p ON f.plugin_id = p.plugin_id
GROUP BY h.host_id, h.ip_address, h.scan_target, h.scan_target_type,
         f.scan_id, s.scan_name, s.created_at;
"""

# Combined schema for backward compatibility (if needed)
# Most code should use SCHEMA_SQL_TABLES and SCHEMA_SQL_VIEWS separately
SCHEMA_SQL = SCHEMA_SQL_TABLES + "\n" + SCHEMA_SQL_VIEWS


# ========== Connection Management ==========

def get_connection(database_path: Optional[Path] = None) -> sqlite3.Connection:
    """Get SQLite connection with optimizations enabled.

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        SQLite connection with WAL mode and foreign keys enabled
    """
    db_path = database_path or DATABASE_PATH

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  # Enable dict-like access

    # Enable optimizations
    conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
    conn.execute("PRAGMA foreign_keys=ON")   # Referential integrity
    conn.execute("PRAGMA synchronous=NORMAL")  # Performance
    conn.execute("PRAGMA temp_store=MEMORY")  # Temp tables in memory
    conn.execute("PRAGMA cache_size=-64000")  # 64MB cache

    return conn


@contextmanager
def db_transaction(
    conn: Optional[sqlite3.Connection] = None,
    database_path: Optional[Path] = None
) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database transactions with auto-commit/rollback.

    Args:
        conn: Existing connection (if None, creates new connection)
        database_path: Path to database (only used if conn is None)

    Yields:
        SQLite connection

    Example:
        with db_transaction() as conn:
            conn.execute("INSERT INTO scans ...")
            conn.execute("INSERT INTO findings ...")
        # Auto-committed on success, rolled back on exception
    """
    if conn is None:
        conn = get_connection(database_path)
        close_on_exit = True
    else:
        close_on_exit = False

    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        log_error(f"Database transaction failed: {e}")
        raise
    finally:
        if close_on_exit:
            conn.close()


# ========== Schema Initialization ==========

def initialize_database(database_path: Optional[Path] = None) -> bool:
    """Initialize database schema with final structure.

    Creates all tables, views, and populates foundation tables.
    Safe to call multiple times (CREATE TABLE IF NOT EXISTS).

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        True if initialization succeeded, False otherwise
    """
    db_path = database_path or DATABASE_PATH

    try:
        with db_transaction(database_path=db_path) as conn:
            # Create all tables
            conn.executescript(SCHEMA_SQL_TABLES)

            # Populate foundation tables (INSERT OR IGNORE for idempotency)
            conn.executemany(
                "INSERT OR IGNORE INTO severity_levels VALUES (?, ?, ?, ?)",
                [
                    (4, 'Critical', 4, '#8B0000'),
                    (3, 'High', 3, '#FF4500'),
                    (2, 'Medium', 2, '#FFA500'),
                    (1, 'Low', 1, '#FFD700'),
                    (0, 'Info', 0, '#4682B4'),
                ]
            )

            conn.executemany(
                "INSERT OR IGNORE INTO artifact_types (type_name, file_extension, description) VALUES (?, ?, ?)",
                [
                    ('nmap_xml', '.xml', 'Nmap XML output'),
                    ('nmap_gnmap', '.gnmap', 'Nmap greppable output'),
                    ('nmap_nmap', '.nmap', 'Nmap normal output'),
                    ('netexec_txt', '.txt', 'NetExec text output'),
                    ('log', '.log', 'Tool execution log'),
                ]
            )

            # Create views
            conn.executescript(SCHEMA_SQL_VIEWS)

        log_info("Database schema initialized successfully")
        return True

    except Exception as e:
        log_error(f"Failed to initialize database: {e}")
        return False


# ========== Utility Functions ==========

def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Hexadecimal SHA256 hash string
    """
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)

    return sha256.hexdigest()


def query_one(
    conn: sqlite3.Connection,
    query: str,
    params: tuple[Any, ...] = ()
) -> Optional[sqlite3.Row]:
    """Execute query and return single row.

    Args:
        conn: Database connection
        query: SQL query
        params: Query parameters

    Returns:
        Single row or None if no results
    """
    cursor = conn.execute(query, params)
    return cast(Optional[sqlite3.Row], cursor.fetchone())


def query_all(
    conn: sqlite3.Connection,
    query: str,
    params: tuple[Any, ...] = ()
) -> list[sqlite3.Row]:
    """Execute query and return all rows.

    Args:
        conn: Database connection
        query: SQL query
        params: Query parameters

    Returns:
        List of rows
    """
    cursor = conn.execute(query, params)
    return cursor.fetchall()


# ========== Database Health Checks ==========

def check_database_health(database_path: Optional[Path] = None) -> bool:
    """Check database integrity and connectivity.

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        True if database is healthy, False otherwise
    """
    db_path = database_path or DATABASE_PATH

    try:
        with db_transaction(database_path=db_path) as conn:
            # Check integrity
            cursor = conn.execute("PRAGMA integrity_check")
            result = cursor.fetchone()

            if result and result[0] != "ok":
                log_error(f"Database integrity check failed: {result[0]}")
                return False

            # Check tables exist
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
            )
            if not cursor.fetchone():
                log_error("Database health check failed: missing required 'scans' table")
                log_error("This is non-fatal - initialization will attempt to repair the schema")
                return False

        return True

    except Exception as e:
        log_error(f"Database health check failed: {e}")
        return False


# ========== Auto-initialization ==========

# Note: Database initialization removed from module import to prevent premature logging.
# Database is now initialized explicitly in cerno.py:main_callback() after logger setup.
# Call initialize_database() from your main entry point after init_logger().

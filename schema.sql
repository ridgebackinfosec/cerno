-- ============================================================================
-- CERNO DATABASE SCHEMA (Version 2.1.12 - Database-First Naming)
-- ============================================================================
-- SQLite schema for tracking Nessus findings, review state, tool executions,
-- and generated artifacts. This file serves as reference documentation.
--
-- Database location: ~/.cerno/cerno.db (global, cross-scan queries)
-- Schema version: 1 (single-version, normalized structure)
--
-- IMPORTANT: This file is DOCUMENTATION ONLY
-- - Actual schema initialization: cerno_pkg/database.py (SCHEMA_SQL_TABLES + SCHEMA_SQL_VIEWS)
-- - Schema is created directly in normalized form on first run
-- - No migration system (breaking changes require major version bump and re-import)
--
-- KEY IMPROVEMENTS IN v2.x:
-- - Normalized host/port tables for cross-scan tracking
-- - Foundation lookup tables (severity_levels, artifact_types)
-- - SQL views for computed statistics (no redundant cached data)
-- - Audit logging support
-- - Foreign key constraints throughout
-- ============================================================================

-- ============================================================================
-- SCANS: Top-level scan tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL UNIQUE,
    nessus_file_path TEXT,              -- Original .nessus file path
    nessus_file_hash TEXT,              -- SHA256 of .nessus file for change detection
    export_root TEXT NOT NULL,          -- Where plugin .txt files are stored
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_reviewed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(scan_name);

-- ============================================================================
-- FOUNDATION TABLES: Normalized reference data
-- ============================================================================

-- Severity levels lookup table (normalized reference data)
CREATE TABLE IF NOT EXISTS severity_levels (
    severity_int INTEGER PRIMARY KEY,
    severity_label TEXT NOT NULL,
    severity_order INTEGER NOT NULL,
    color_hint TEXT,
    CONSTRAINT unique_severity_label UNIQUE (severity_label)
);

-- Pre-populated with:
-- (4, 'Critical', 4, '#8B0000')
-- (3, 'High', 3, '#FF4500')
-- (2, 'Medium', 2, '#FFA500')
-- (1, 'Low', 1, '#FFD700')
-- (0, 'Info', 0, '#4682B4')

-- Artifact types lookup table (enforces consistency)
CREATE TABLE IF NOT EXISTS artifact_types (
    artifact_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_name TEXT NOT NULL UNIQUE,
    file_extension TEXT,
    description TEXT,
    parser_module TEXT
);

-- Pre-populated with:
-- ('nmap_xml', '.xml', 'Nmap XML output')
-- ('nmap_gnmap', '.gnmap', 'Nmap greppable output')
-- ('nmap_txt', '.txt', 'Nmap text output')
-- ('netexec_txt', '.txt', 'NetExec text output')
-- ('log', '.log', 'Tool execution log')

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

-- ============================================================================
-- NORMALIZED HOST/PORT TRACKING (Cross-Scan Capabilities)
-- ============================================================================

-- Hosts table (normalized host data across scans)
-- Enables cross-scan queries: "show all findings for host X across all scans"
CREATE TABLE IF NOT EXISTS hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_address TEXT NOT NULL UNIQUE,
    host_type TEXT CHECK(host_type IN ('ipv4', 'ipv6', 'hostname')) NOT NULL,
    reverse_dns TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hosts_address ON hosts(host_address);
CREATE INDEX IF NOT EXISTS idx_hosts_type ON hosts(host_type);

-- Ports table (port metadata)
CREATE TABLE IF NOT EXISTS ports (
    port_number INTEGER PRIMARY KEY CHECK(port_number BETWEEN 1 AND 65535),
    service_name TEXT,
    description TEXT
);

-- ============================================================================
-- PLUGINS: Plugin metadata (Nessus plugin ID - internal reference only)
-- ============================================================================
-- NOTE: "plugin" is internal terminology. User-facing commands use "findings"
-- ============================================================================
CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,      -- Nessus plugin ID (e.g., 57608)
    plugin_name TEXT NOT NULL,
    severity_int INTEGER NOT NULL,      -- 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical

    -- REMOVED in v2.x: severity_label (now in severity_levels lookup table)
    -- Use v_plugins_with_severity view to get labels

    has_metasploit BOOLEAN DEFAULT 0,
    cvss3_score REAL,                   -- CVSS v3 base score
    cvss2_score REAL,                   -- CVSS v2 base score (fallback)

    -- Metasploit module names (JSON array, extracted from .nessus XML)
    metasploit_names TEXT,              -- JSON: ["Chargen Probe Utility", "Another Module"]

    -- CVE associations (JSON array, extracted from .nessus XML)
    cves TEXT,                          -- JSON: ["CVE-2023-1234", "CVE-2023-5678"]

    -- Tenable plugin URL
    plugin_url TEXT,                    -- https://www.tenable.com/plugins/nessus/{plugin_id}

    -- Metadata fetch timestamp
    metadata_fetched_at TIMESTAMP,

    CONSTRAINT severity_range CHECK (severity_int BETWEEN 0 AND 4),
    FOREIGN KEY (severity_int) REFERENCES severity_levels(severity_int)
);

CREATE INDEX IF NOT EXISTS idx_plugins_severity ON plugins(severity_int);
CREATE INDEX IF NOT EXISTS idx_plugins_metasploit ON plugins(has_metasploit);

-- ============================================================================
-- FINDINGS: Vulnerability findings per scan (one per plugin per scan)
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    plugin_id INTEGER NOT NULL,
    review_state TEXT DEFAULT 'pending',
    reviewed_at TIMESTAMP,
    reviewed_by TEXT,
    review_notes TEXT,

    -- REMOVED in v2.x: host_count, port_count, file_path, severity_dir,
    --                  file_created_at, file_modified_at, last_parsed_at
    -- Use v_finding_stats view to get host/port counts

    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id),
    CONSTRAINT valid_review_state CHECK (review_state IN ('pending', 'reviewed', 'completed', 'skipped')),
    CONSTRAINT unique_scan_plugin UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_plugin ON findings(plugin_id);
CREATE INDEX IF NOT EXISTS idx_findings_review_state ON findings(review_state);

-- ============================================================================
-- FINDING_AFFECTED_HOSTS: Host:port combinations per finding (Normalized)
-- ============================================================================
CREATE TABLE IF NOT EXISTS finding_affected_hosts (
    fah_id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Renamed from pfh_id in v2.1.12
    finding_id INTEGER NOT NULL,

    -- CHANGED in v2.x: host and port are now foreign keys to normalized tables
    host_id INTEGER NOT NULL,           -- FK to hosts table
    port_number INTEGER,                -- FK to ports table (NULL if no port)

    -- REMOVED in v2.x: host TEXT, is_ipv4, is_ipv6
    -- Host metadata now in hosts table

    -- Plugin output (extracted from .nessus <plugin_output> element)
    plugin_output TEXT,                 -- Host-specific Nessus scanner output

    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    FOREIGN KEY (port_number) REFERENCES ports(port_number),
    CONSTRAINT unique_file_host_port UNIQUE (finding_id, host_id, port_number)
);

CREATE INDEX IF NOT EXISTS idx_fah_file ON finding_affected_hosts(finding_id);
CREATE INDEX IF NOT EXISTS idx_fah_host ON finding_affected_hosts(host_id);
CREATE INDEX IF NOT EXISTS idx_fah_port ON finding_affected_hosts(port_number);

-- ============================================================================
-- SESSIONS: Review session tracking (INTERNAL - no user-facing commands)
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,

    session_start TIMESTAMP NOT NULL,
    session_end TIMESTAMP,

    -- REMOVED in v2.x: duration_seconds, files_reviewed, files_completed,
    --                  files_skipped, tools_executed, cves_extracted
    -- Use v_session_stats view to get computed statistics

    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_scan ON sessions(scan_id);

-- ============================================================================
-- TOOL_EXECUTIONS: Track every tool run
-- ============================================================================
CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,                 -- NULL if run outside session
    finding_id INTEGER,                    -- Which plugin file triggered this

    -- Tool identification
    tool_name TEXT NOT NULL,            -- 'nmap', 'netexec', 'metasploit', 'custom'
    tool_protocol TEXT,                 -- For netexec: 'smb', 'ssh', 'rdp', etc.

    -- Command details
    command_text TEXT NOT NULL,         -- Full command as string
    command_args TEXT,                  -- JSON array of arguments

    -- Execution metadata
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_code INTEGER,
    duration_seconds REAL,

    -- Host/port context
    host_count INTEGER,
    sampled BOOLEAN DEFAULT 0,          -- Was host list sampled (>5 hosts)?
    ports TEXT,                         -- Comma-separated port list

    -- Sudo usage
    used_sudo BOOLEAN DEFAULT 0,

    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_file ON tool_executions(finding_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);

-- ============================================================================
-- ARTIFACTS: Track all generated output files
-- ============================================================================
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER,               -- NULL if manually created

    -- Artifact identification
    artifact_path TEXT NOT NULL UNIQUE, -- Absolute path
    artifact_type_id INTEGER,           -- FK to artifact_types (CHANGED in v2.x)

    -- REMOVED in v2.x: artifact_type TEXT
    -- Use v_artifacts_with_types view to get type names

    -- File metadata
    file_size_bytes INTEGER,
    file_hash TEXT,                     -- SHA256

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,

    -- Artifact-specific metadata (JSON)
    metadata TEXT,                      -- JSON: {"nse_scripts": [...], "udp": true, ...}

    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE SET NULL,
    FOREIGN KEY (artifact_type_id) REFERENCES artifact_types(artifact_type_id)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_execution ON artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type_id);

-- ============================================================================
-- WORKFLOWS: Custom workflow tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS workflow_executions (
    workflow_execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    workflow_name TEXT NOT NULL,

    -- Workflow tracking
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT 0,

    -- Workflow results (JSON)
    results TEXT,                       -- JSON: {"step1": "ok", "step2": "failed", ...}

    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_file ON workflow_executions(finding_id);

-- ============================================================================
-- VIEWS: Computed Statistics (NEW in v2.x)
-- ============================================================================
-- These views provide computed aggregates without storing redundant data in tables
-- This eliminates data consistency issues and reduces storage overhead

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

-- Host findings summary (cross-scan tracking - NEW capability in v2.x)
CREATE VIEW IF NOT EXISTS v_host_findings AS
SELECT
    h.host_id,
    h.host_address,
    h.host_type,
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
GROUP BY h.host_id, h.host_address, h.host_type, h.first_seen, h.last_seen;

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

-- ============================================================================
-- PRAGMA SETTINGS (applied at connection time by database.py)
-- ============================================================================
-- PRAGMA journal_mode=WAL;        -- Write-Ahead Logging for concurrency
-- PRAGMA foreign_keys=ON;         -- Enable referential integrity
-- PRAGMA synchronous=NORMAL;      -- Balance between safety and performance
-- PRAGMA temp_store=MEMORY;       -- Keep temp tables in memory
-- PRAGMA cache_size=-64000;       -- 64MB cache

-- ============================================================================
-- QUERY EXAMPLES (v2.x Normalized Schema)
-- ============================================================================

-- Example 1: Get all findings for a specific host across all scans
-- SELECT
--     h.host_address,
--     s.scan_name,
--     p.plugin_name,
--     sl.severity_label,
--     f.review_state
-- FROM hosts h
-- JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
-- JOIN findings f ON fah.finding_id = f.finding_id
-- JOIN plugins p ON f.plugin_id = p.plugin_id
-- JOIN severity_levels sl ON p.severity_int = sl.severity_int
-- JOIN scans s ON f.scan_id = s.scan_id
-- WHERE h.host_address = '192.168.1.10'
-- ORDER BY s.created_at DESC, sl.severity_order DESC;

-- Example 2: Get finding with host/port counts using view
-- SELECT * FROM v_finding_stats WHERE finding_id = 123;

-- Example 3: Get session statistics using view
-- SELECT * FROM v_session_stats ORDER BY session_start DESC LIMIT 5;

-- Example 4: Get all hosts that appeared in multiple scans
-- SELECT
--     host_address,
--     scan_count,
--     finding_count,
--     first_seen,
--     last_seen
-- FROM v_host_findings
-- WHERE scan_count > 1
-- ORDER BY scan_count DESC;

-- Example 5: Get plugins with severity labels using view
-- SELECT plugin_name, severity_label, cvss3_score
-- FROM v_plugins_with_severity
-- WHERE severity_int >= 3
-- ORDER BY severity_int DESC, cvss3_score DESC;

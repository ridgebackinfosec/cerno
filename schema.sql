-- ============================================================================
-- CERNO DATABASE SCHEMA (schema version 4)
-- ============================================================================
-- Reference copy of the SQLite schema. The authoritative DDL is
-- cerno_pkg/database.py (SCHEMA_SQL_TABLES + SCHEMA_SQL_VIEWS);
-- tests/test_database.py checks that this file defines the same tables,
-- views and indexes.
--
-- Database location: ~/.cerno/cerno.db (global, cross-scan queries)
-- Schema version: 4, stored in PRAGMA user_version. Older databases
--   are rejected with SchemaVersionError (no migration system; re-import).
-- Column-by-column documentation: docs/DATABASE.md
-- ============================================================================


CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL UNIQUE,
    nessus_file_path TEXT,                  -- Original .nessus file path
    nessus_file_hash TEXT,                  -- SHA256 of .nessus file for change detection
    export_root TEXT NOT NULL,              -- Root directory recorded at import (no files are written)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_reviewed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(scan_name);

CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,          -- Nessus plugin ID (e.g., 57608)
    plugin_name TEXT NOT NULL,
    severity_int INTEGER NOT NULL,          -- 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    has_metasploit BOOLEAN DEFAULT 0,
    cvss3_score REAL,                       -- CVSS v3 base score
    cvss2_score REAL,                       -- CVSS v2 base score (fallback)
    metasploit_names TEXT,                  -- JSON: ["Chargen Probe Utility", "Another Module"]
    cves TEXT,                              -- JSON: ["CVE-2023-1234", "CVE-2023-5678"]
    plugin_url TEXT,                        -- https://www.tenable.com/plugins/nessus/{plugin_id}
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
    review_state TEXT NOT NULL DEFAULT 'unreviewed',
    reviewed_at TIMESTAMP,
    reviewed_by TEXT,
    review_notes TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id),
    CONSTRAINT valid_review_state CHECK (review_state IN ('unreviewed', 'in_progress', 'done')),
    CONSTRAINT unique_scan_plugin UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_plugin ON findings(plugin_id);
CREATE INDEX IF NOT EXISTS idx_findings_review_state ON findings(review_state);
CREATE INDEX IF NOT EXISTS idx_findings_scan_plugin ON findings(scan_id, plugin_id);

CREATE TABLE IF NOT EXISTS finding_affected_hosts (
    fah_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,               -- FK to hosts table
    port_number INTEGER,                    -- FK to ports table (NULL if no port)
    plugin_output TEXT,                     -- Host-specific Nessus scanner output
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

CREATE TABLE IF NOT EXISTS session_scans (
    session_id INTEGER NOT NULL,
    scan_id    INTEGER NOT NULL,
    PRIMARY KEY (session_id, scan_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id)    REFERENCES scans(scan_id)    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_scans_scan_id ON session_scans(scan_id);

CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,                     -- NULL if run outside session
    finding_id INTEGER,                     -- Finding the run is attributed to (NULL = unattributed)
    tool_name TEXT NOT NULL,                -- 'nmap', 'netexec', 'metasploit', 'custom'
    tool_protocol TEXT,                     -- For netexec: 'smb', 'ssh', 'rdp', etc.
    command_text TEXT NOT NULL,             -- Full command as string
    command_args TEXT,                      -- JSON array of arguments
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_code INTEGER,
    duration_seconds REAL,
    host_count INTEGER,
    sampled BOOLEAN DEFAULT 0,              -- Was host list sampled (>5 hosts)?
    ports TEXT,                             -- Comma-separated port list
    used_sudo BOOLEAN DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_finding ON tool_executions(finding_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER,                   -- NULL if manually created
    artifact_path TEXT NOT NULL UNIQUE,     -- Absolute path
    artifact_type_id INTEGER,               -- FK to artifact_types
    file_size_bytes INTEGER,
    file_hash TEXT,                         -- SHA256
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,
    metadata TEXT,                          -- JSON: {"nse_scripts": [...], "udp": true, ...}
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
    results TEXT,                           -- JSON: {"step1": "ok", "step2": "failed", ...}
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_finding ON workflow_executions(finding_id);

-- Severity levels lookup table (normalized reference data)
-- Severity levels lookup table (normalized reference data)
CREATE TABLE IF NOT EXISTS severity_levels (
    severity_int INTEGER PRIMARY KEY,
    severity_label TEXT NOT NULL,
    severity_order INTEGER NOT NULL,
    color_hint TEXT,
    CONSTRAINT unique_severity_label UNIQUE (severity_label)
);

-- Artifact types lookup table (enforces consistency)
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

-- Audit log (reserved: no triggers or code write to it yet)
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
-- Hosts table (normalized host data across scans)
-- Supports both IP-targeted and FQDN-targeted scans:
--   - ip_address: Always the resolved IP (from host-ip tag)
--   - scan_target: What was scanned (IP or FQDN from ReportHost@name)
--   - Composite unique: same IP via same target = same host
-- Enables cross-scan queries: "show all findings for host X across all scans"
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
-- Ports table (port metadata)
CREATE TABLE IF NOT EXISTS ports (
    port_number INTEGER PRIMARY KEY CHECK(port_number BETWEEN 1 AND 65535),
    service_name TEXT,
    description TEXT
);

-- Host services table (per-scan service discovery from Nessus)
-- Maps (host_id, port_number, protocol) to the svc_name discovered by Nessus
-- Same port may have different services on different hosts, so this is
-- normalized per-host rather than stored in the global ports table
CREATE TABLE IF NOT EXISTS host_services (
    host_service_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    port_number INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    svc_name TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    FOREIGN KEY (port_number) REFERENCES ports(port_number),
    UNIQUE(scan_id, host_id, port_number, protocol)
);

CREATE INDEX IF NOT EXISTS idx_host_services_scan ON host_services(scan_id);
CREATE INDEX IF NOT EXISTS idx_host_services_host ON host_services(host_id);
CREATE INDEX IF NOT EXISTS idx_host_services_svc ON host_services(svc_name);

-- Claude Assistant conversation history
-- Stores per-finding chat turns; cascades on finding delete
CREATE TABLE IF NOT EXISTS claude_conversations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_claude_conversations_finding
    ON claude_conversations(finding_id);

-- Claude Assistant aggregate conversations
-- Stores chat turns for severity-menu and findings-list scope conversations.
-- Keyed by a context_key string (not a FK) since scope spans multiple findings.
CREATE TABLE IF NOT EXISTS claude_aggregate_conversations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    context_key TEXT NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_claude_aggregate_context
    ON claude_aggregate_conversations(context_key);

-- ========== Execution -> Data Loop (schema v4) ==========

-- Lookup: verification verdict types (truth, distinct from review_state)
CREATE TABLE IF NOT EXISTS verdict_types (
    verdict_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT NOT NULL UNIQUE,
    description     TEXT
);

-- Lookup: NSE vuln-script verdict classifications
CREATE TABLE IF NOT EXISTS nse_verdicts (
    nse_verdict_id INTEGER PRIMARY KEY AUTOINCREMENT,
    label          TEXT NOT NULL UNIQUE
);

-- Lookup: nmap port states
CREATE TABLE IF NOT EXISTS port_states (
    port_state_id INTEGER PRIMARY KEY AUTOINCREMENT,
    label         TEXT NOT NULL UNIQUE
);

-- Live-verified open ports from a tool run (provenance = execution_id)
-- Lookup tables (seeded in initialize_database):
--   verdict_types(verdict_type_id PK, label UNIQUE, description)
--       seeded: confirmed, false_positive, unable
--   nse_verdicts(nse_verdict_id PK, label UNIQUE)
--       seeded: VULNERABLE, NOT_VULNERABLE, LIKELY_VULNERABLE, UNKNOWN
--   port_states(port_state_id PK, label UNIQUE)
--       seeded: open, closed, filtered, open|filtered, closed|filtered, unfiltered
-- Fact tables (provenance = execution_id; idempotent per execution):
CREATE TABLE IF NOT EXISTS verified_ports (
    verified_port_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id     INTEGER NOT NULL,
    host_id          INTEGER NOT NULL,
    port_number      INTEGER,
    protocol         TEXT NOT NULL DEFAULT 'tcp',
    port_state_id    INTEGER,
    service_name     TEXT,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    FOREIGN KEY (port_number) REFERENCES ports(port_number),
    FOREIGN KEY (port_state_id) REFERENCES port_states(port_state_id),
    UNIQUE (execution_id, host_id, port_number, protocol)
);

CREATE INDEX IF NOT EXISTS idx_verified_ports_execution ON verified_ports(execution_id);
CREATE INDEX IF NOT EXISTS idx_verified_ports_host ON verified_ports(host_id);
CREATE INDEX IF NOT EXISTS idx_verified_ports_port ON verified_ports(port_number);

-- NSE script results, especially vuln-script verdicts (provenance = execution_id)
-- port_number NULL marks a host script (vs a port script)
CREATE TABLE IF NOT EXISTS nse_script_results (
    nse_result_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id   INTEGER NOT NULL,
    host_id        INTEGER NOT NULL,
    port_number    INTEGER,                 -- NULL = host script
    script_id      TEXT NOT NULL,
    nse_verdict_id INTEGER,
    output         TEXT,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    FOREIGN KEY (port_number) REFERENCES ports(port_number),
    FOREIGN KEY (nse_verdict_id) REFERENCES nse_verdicts(nse_verdict_id),
    UNIQUE (execution_id, host_id, port_number, script_id)
);

CREATE INDEX IF NOT EXISTS idx_nse_results_execution ON nse_script_results(execution_id);
CREATE INDEX IF NOT EXISTS idx_nse_results_host ON nse_script_results(host_id);
CREATE INDEX IF NOT EXISTS idx_nse_results_verdict ON nse_script_results(nse_verdict_id);

-- Point-in-time snapshot of nxc security flags (provenance = execution_id).
-- Credentials and shares are NOT duplicated here; they stay live-read via nxc_db.
CREATE TABLE IF NOT EXISTS nxc_flag_observations (
    nxc_flag_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER NOT NULL,
    host_id      INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    flag_name    TEXT NOT NULL,
    flag_value   INTEGER NOT NULL CHECK(flag_value IN (0, 1)),
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    UNIQUE (execution_id, host_id, protocol, flag_name)
);

CREATE INDEX IF NOT EXISTS idx_nxc_flags_execution ON nxc_flag_observations(execution_id);
CREATE INDEX IF NOT EXISTS idx_nxc_flags_host ON nxc_flag_observations(host_id);

-- Finding verification verdicts (append-only history; current = latest created_at)
-- Verdict tables (append-only history + evidence links):
CREATE TABLE IF NOT EXISTS finding_verdicts (
    verdict_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL,
    verdict_type_id INTEGER NOT NULL,
    note            TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by      TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (verdict_type_id) REFERENCES verdict_types(verdict_type_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_verdicts_finding ON finding_verdicts(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_verdicts_created ON finding_verdicts(created_at);

-- Evidence backing a verdict (links to the execution/artifact/NSE result that proves it)
CREATE TABLE IF NOT EXISTS verdict_evidence (
    evidence_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id    INTEGER NOT NULL,
    execution_id  INTEGER,
    artifact_id   INTEGER,
    nse_result_id INTEGER,
    note          TEXT,
    FOREIGN KEY (verdict_id) REFERENCES finding_verdicts(verdict_id) ON DELETE CASCADE,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE SET NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
    FOREIGN KEY (nse_result_id) REFERENCES nse_script_results(nse_result_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_verdict_evidence_verdict ON verdict_evidence(verdict_id);

-- ============================================================================
-- SEED DATA (inserted by initialize_database(), INSERT OR IGNORE)
-- ============================================================================
-- severity_levels: (4,'Critical',4,'#8B0000') (3,'High',3,'#FF4500')
--   (2,'Medium',2,'#FFA500') (1,'Low',1,'#FFD700') (0,'Info',0,'#4682B4')
-- artifact_types (type_name, file_extension, description):
--   ('nmap_xml','.xml','Nmap XML output') ('nmap_gnmap','.gnmap','Nmap greppable output')
--   ('nmap_nmap','.nmap','Nmap normal output') ('netexec_txt','.txt','NetExec text output')
--   ('log','.log','Tool execution log')
-- verdict_types: confirmed, false_positive, unable
-- nse_verdicts: VULNERABLE, NOT_VULNERABLE, LIKELY_VULNERABLE, UNKNOWN
-- port_states: open, closed, filtered, open|filtered, closed|filtered, unfiltered

-- ============================================================================
-- VIEWS (computed statistics; nothing derived is stored in tables)
-- ============================================================================
-- ========== VIEWS (Computed Statistics) ==========
-- These views provide computed aggregates without storing redundant data in tables

-- Finding statistics (replaces host_count, port_count columns)
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
-- Session statistics (replaces aggregate columns in sessions table)
CREATE VIEW IF NOT EXISTS v_session_stats AS
SELECT
    s.session_id,
    s.scan_id,
    s.session_start,
    s.session_end,
    (julianday(s.session_end) - julianday(s.session_start)) * 86400 AS duration_seconds,
    COUNT(DISTINCT CASE WHEN f.review_state = 'in_progress' THEN f.finding_id END) as files_in_progress,
    COUNT(DISTINCT CASE WHEN f.review_state = 'done' THEN f.finding_id END) as files_done,
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
-- Host findings summary (cross-scan tracking)
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
-- Scan plugin summary (for cross-scan comparison)
-- Shows all plugins present in each scan with affected host/port counts
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

-- HTTP/HTTPS services view (for URL generation and tool suggestions)
-- Identifies web services using svc_name heuristics matching Nessus conventions
CREATE VIEW IF NOT EXISTS v_http_services AS
SELECT
    hs.host_service_id,
    hs.scan_id,
    h.host_id,
    h.scan_target,
    hs.port_number,
    hs.protocol,
    hs.svc_name,
    CASE
        WHEN hs.svc_name IN ('https?', 'https') THEN 'https'
        WHEN hs.port_number IN (443, 8443) THEN 'https'
        WHEN hs.svc_name IN ('www', 'http?', 'http') THEN 'http'
        WHEN hs.port_number IN (80, 8080) THEN 'http'
        ELSE NULL
    END as http_scheme
FROM host_services hs
JOIN hosts h ON hs.host_id = h.host_id
WHERE hs.svc_name IN ('www', 'http?', 'https?', 'http', 'https')
   OR hs.port_number IN (80, 443, 8080, 8443);

-- ========== Execution -> Data Loop views (schema v4) ==========

-- Current (latest) verdict per finding
CREATE VIEW IF NOT EXISTS v_finding_current_verdict AS
SELECT
    fv.finding_id,
    fv.verdict_id,
    fv.verdict_type_id,
    vt.label AS verdict_label,
    fv.note,
    fv.created_at,
    fv.created_by
FROM finding_verdicts fv
JOIN verdict_types vt ON fv.verdict_type_id = vt.verdict_type_id
WHERE fv.created_at = (
    SELECT MAX(fv2.created_at)
    FROM finding_verdicts fv2
    WHERE fv2.finding_id = fv.finding_id
)
AND fv.verdict_id = (
    SELECT MAX(fv3.verdict_id)
    FROM finding_verdicts fv3
    WHERE fv3.finding_id = fv.finding_id
      AND fv3.created_at = fv.created_at
);

-- NSE script results with their verdict label resolved
CREATE VIEW IF NOT EXISTS v_nse_results_with_verdict AS
SELECT
    nsr.nse_result_id,
    nsr.execution_id,
    nsr.host_id,
    nsr.port_number,
    nsr.script_id,
    nsr.nse_verdict_id,
    nv.label AS verdict_label,
    nsr.output,
    nsr.created_at
FROM nse_script_results nsr
LEFT JOIN nse_verdicts nv ON nsr.nse_verdict_id = nv.nse_verdict_id;

-- Live-verified fact counts per finding (via the execution's finding_id)
CREATE VIEW IF NOT EXISTS v_finding_verified_stats AS
SELECT
    te.finding_id,
    COUNT(DISTINCT vp.verified_port_id) AS verified_port_count,
    COUNT(DISTINCT nsr.nse_result_id) AS nse_result_count,
    COUNT(DISTINCT CASE WHEN nv.label = 'VULNERABLE' THEN nsr.nse_result_id END) AS vulnerable_count
FROM tool_executions te
LEFT JOIN verified_ports vp ON vp.execution_id = te.execution_id
LEFT JOIN nse_script_results nsr ON nsr.execution_id = te.execution_id
LEFT JOIN nse_verdicts nv ON nsr.nse_verdict_id = nv.nse_verdict_id
WHERE te.finding_id IS NOT NULL
GROUP BY te.finding_id;

-- ============================================================================
-- PRAGMA SETTINGS (applied at connection time by database.py)
-- ============================================================================
-- PRAGMA journal_mode=WAL;        -- Write-Ahead Logging for concurrency
-- PRAGMA foreign_keys=ON;         -- Enable referential integrity
-- PRAGMA synchronous=NORMAL;      -- Balance between safety and performance
-- PRAGMA temp_store=MEMORY;       -- Keep temp tables in memory
-- PRAGMA cache_size=-64000;       -- 64MB cache

-- ============================================================================
-- QUERY EXAMPLES
-- ============================================================================

-- Example 1: Get all findings for a specific host across all scans
-- SELECT
--     h.ip_address,
--     h.scan_target,
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
-- WHERE h.ip_address = '192.168.1.10'
-- ORDER BY s.created_at DESC, sl.severity_order DESC;

-- Example 2: Get finding with host/port counts using view
-- SELECT * FROM v_finding_stats WHERE finding_id = 123;

-- Example 3: Get session statistics using view
-- SELECT * FROM v_session_stats ORDER BY session_start DESC LIMIT 5;

-- Example 4: Get all hosts that appeared in multiple scans
-- SELECT
--     ip_address,
--     scan_target,
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

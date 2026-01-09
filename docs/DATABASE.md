# Cerno Database Documentation

Cerno uses an **integrated SQLite database** with a fully normalized schema for tracking scan metadata, review state, tool executions, and generated artifacts. The database provides an audit trail, enables historical analysis, cross-scan queries, and maintains referential integrity through foreign key constraints.

---

## Table of Contents

- [Overview](#overview)
- [Database Location](#database-location)
- [Normalized Schema Architecture](#normalized-schema-architecture)
- [Schema Overview](#schema-overview)
- [Foundation Tables](#foundation-tables)
- [Core Tables](#core-tables)
- [SQL Views (Computed Statistics)](#sql-views-computed-statistics)
- [Query Examples](#query-examples)
- [Cross-Scan Tracking](#cross-scan-tracking)
- [Schema Reference](#schema-reference)

---

## Overview

The Cerno database tracks:

- **Scans**: Nessus export metadata (scan name, export root, .nessus file hash)
- **Plugins**: Vulnerability definitions (plugin ID, name, severity, CVSS scores, CVEs, Metasploit modules)
- **Findings**: Individual vulnerability findings per scan (review state, reviewed timestamp)
- **Hosts & Ports**: Normalized host/port data with cross-scan tracking
- **Sessions**: Review session state (start time, duration via SQL view)
- **Tool Executions**: Commands run during reviews (tool name, exit codes, duration)
- **Artifacts**: Generated files from tool runs (file paths, SHA256 hashes, sizes)
- **Workflows**: Custom workflow execution tracking

All operations work **transparently** - no manual database management required.

---

## Database Location

**Default Path**: `~/.cerno/cerno.db`

The database is global across all scans, enabling cross-scan queries and historical analysis.

**Directory**: `~/.cerno/` is created automatically on first use.

**Schema Version**: 1 (single-version, normalized structure - no migration system)

---

## Normalized Schema Architecture

Cerno uses a **fully normalized database schema** following relational best practices.

### Key Design Principles

1. **Normalized Lookup Tables**
   - `severity_levels` - Centralized severity reference data
   - `artifact_types` - Standardized artifact type definitions
   - `hosts` - Deduplicated host data across scans
   - `ports` - Port metadata

2. **Computed Values via Views**
   - Host/port counts computed on-demand via SQL views
   - Session statistics aggregated dynamically
   - No cached or redundant data stored in columns

3. **SQL Views for Statistics**
   - `v_finding_stats` - Host/port counts per finding
   - `v_session_stats` - Session duration and file counts
   - `v_plugins_with_severity` - Plugins with severity labels
   - `v_host_findings` - Cross-scan host analysis
   - `v_artifacts_with_types` - Artifacts with type names

4. **Foreign Key Constraints Throughout**
   - All relationships enforced at database level
   - Cascade deletes where appropriate
   - Referential integrity guaranteed

### Benefits

- **Zero Data Redundancy**: Single source of truth for all data
- **Always Accurate**: Computed values never stale
- **Cross-Scan Queries**: Track hosts across multiple scans
- **Data Integrity**: Foreign keys prevent orphaned records
- **Better Performance**: Optimized indexes on all foreign keys

---

## Schema Overview

The database consists of **13 tables** and **5 views**:

### Foundation Tables (Normalized Reference Data)

1. **severity_levels** - Severity definitions (0-4, labels, colors)
2. **artifact_types** - Artifact type definitions
3. **audit_log** - Change tracking for critical tables

### Core Tables

4. **scans** - Top-level scan tracking
5. **plugins** - Plugin metadata (Nessus plugin ID, severity, CVEs)
6. **findings** - Vulnerability findings per scan (review state)
7. **hosts** - Normalized host data (cross-scan tracking)
8. **ports** - Port metadata
9. **finding_affected_hosts** - Host:port combinations per finding (normalized FKs)

### Review & Execution Tracking

10. **sessions** - Review session tracking
11. **tool_executions** - Commands run during reviews
12. **artifacts** - Generated output files
13. **workflow_executions** - Custom workflow tracking

### SQL Views (Computed Statistics)

- **v_finding_stats** - Host/port counts per finding (replaces columns)
- **v_session_stats** - Session statistics (replaces columns)
- **v_plugins_with_severity** - Plugins with severity labels (replaces column)
- **v_host_findings** - Cross-scan host analysis
- **v_artifacts_with_types** - Artifacts with type information (replaces column)

---

## Foundation Tables

### severity_levels

Normalized severity reference data - enforces valid severity values.

| Column | Type | Description |
|---|---|---|
| `severity_int` | INTEGER | Primary key (0-4) |
| `severity_label` | TEXT | "Info", "Low", "Medium", "High", "Critical" |
| `severity_order` | INTEGER | Sort order (0-4) |
| `color_hint` | TEXT | Hex color code for UI rendering |

**Pre-populated Data**:
```sql
(4, 'Critical', 4, '#8B0000')
(3, 'High', 3, '#FF4500')
(2, 'Medium', 2, '#FFA500')
(1, 'Low', 1, '#FFD700')
(0, 'Info', 0, '#4682B4')
```

**Foreign Keys**: Referenced by `plugins.severity_int`

---

### artifact_types

Artifact type definitions - enforces consistent artifact categorization.

| Column | Type | Description |
|---|---|---|
| `artifact_type_id` | INTEGER | Primary key |
| `type_name` | TEXT | Unique type name |
| `file_extension` | TEXT | Expected file extension |
| `description` | TEXT | Human-readable description |
| `parser_module` | TEXT | Future: Python module for parsing |

**Pre-populated Data**:
- `nmap_xml` - Nmap XML output (.xml)
- `nmap_gnmap` - Nmap greppable output (.gnmap)
- `nmap_txt` - Nmap text output (.txt)
- `netexec_txt` - NetExec text output (.txt)
- `log` - Tool execution log (.log)

**Foreign Keys**: Referenced by `artifacts.artifact_type_id`

---

### audit_log

Audit trail for changes to critical tables (future feature).

| Column | Type | Description |
|---|---|---|
| `audit_id` | INTEGER | Primary key |
| `table_name` | TEXT | Table being modified |
| `record_id` | INTEGER | Record ID in that table |
| `action` | TEXT | 'INSERT', 'UPDATE', 'DELETE' |
| `changed_by` | TEXT | User identifier (future) |
| `changed_at` | TIMESTAMP | Change timestamp |
| `old_values` | TEXT | JSON of old values |
| `new_values` | TEXT | JSON of new values |

---

## Core Tables

### scans

Top-level scan tracking - one row per Nessus export.

| Column | Type | Description |
|---|---|---|
| `scan_id` | INTEGER | Primary key (auto-increment) |
| `scan_name` | TEXT | Unique scan name |
| `nessus_file_path` | TEXT | Original .nessus file path |
| `nessus_file_hash` | TEXT | SHA256 of .nessus file for change detection |
| `export_root` | TEXT | Where plugin .txt files are stored |
| `created_at` | TIMESTAMP | Scan creation time |
| `last_reviewed_at` | TIMESTAMP | Last review session timestamp |

**Relationships**: One scan has many `findings` and `sessions`

---

### plugins

Plugin metadata - one row per Nessus plugin ID.

| Column | Type | Description |
|---|---|---|
| `plugin_id` | INTEGER | Primary key - Nessus plugin ID (e.g., 57608) |
| `plugin_name` | TEXT | Plugin name |
| `severity_int` | INTEGER | 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical |
| `has_metasploit` | BOOLEAN | Metasploit module availability |
| `cvss3_score` | REAL | CVSS v3 base score |
| `cvss2_score` | REAL | CVSS v2 base score (fallback) |
| `metasploit_names` | TEXT | JSON array of Metasploit module names |
| `cves` | TEXT | JSON array of CVE IDs |
| `plugin_url` | TEXT | Tenable plugin URL |
| `metadata_fetched_at` | TIMESTAMP | When CVEs were fetched |

**Note**: The `severity_label` is accessed via the `v_plugins_with_severity` view or by JOINing with `severity_levels`.

**Foreign Keys**: `severity_int` → `severity_levels.severity_int`

**Constraints**:
- `CHECK(severity_int BETWEEN 0 AND 4)`

**Note**: "plugin" is internal terminology. User-facing commands use "findings".

**Relationships**: One plugin has many `findings` (across different scans)

---

### hosts

Normalized host data - one row per unique host address across ALL scans.

| Column | Type | Description |
|---|---|---|
| `host_id` | INTEGER | Primary key |
| `host_address` | TEXT | Unique host address (IP or hostname) |
| `host_type` | TEXT | 'ipv4', 'ipv6', or 'hostname' |
| `reverse_dns` | TEXT | Reverse DNS lookup result (future) |
| `first_seen` | TIMESTAMP | First appearance across all scans |
| `last_seen` | TIMESTAMP | Most recent appearance |

**Purpose**: Enables cross-scan host tracking.

**Constraints**:
- `UNIQUE(host_address)`
- `CHECK(host_type IN ('ipv4', 'ipv6', 'hostname'))`

**Relationships**: Referenced by `finding_affected_hosts.host_id`

---

### ports

Port metadata - one row per port number.

| Column | Type | Description |
|---|---|---|
| `port_number` | INTEGER | Primary key (1-65535) |
| `service_name` | TEXT | Common service name (future) |
| `description` | TEXT | Service description (future) |

**Purpose**: Allows port metadata to be maintained separately from host:port combinations.

**Constraints**:
- `CHECK(port_number BETWEEN 1 AND 65535)`

**Relationships**: Referenced by `finding_affected_hosts.port_number`

---

### findings

Finding records - one row per plugin per scan.

| Column | Type | Description |
|---|---|---|
| `finding_id` | INTEGER | Primary key |
| `scan_id` | INTEGER | Foreign key to scans |
| `plugin_id` | INTEGER | Foreign key to plugins |
| `review_state` | TEXT | 'pending', 'reviewed', 'completed', 'skipped' |
| `reviewed_at` | TIMESTAMP | When finding was reviewed |
| `reviewed_by` | TEXT | User tracking (future feature) |
| `review_notes` | TEXT | User notes (future feature) |

**Note**: Host and port counts are computed via `v_finding_stats` view rather than stored as columns. File paths are not stored - findings are referenced by IDs.

**Foreign Keys**:
- `scan_id` → `scans.scan_id` (CASCADE DELETE)
- `plugin_id` → `plugins.plugin_id`

**Constraints**:
- `UNIQUE(scan_id, plugin_id)` - One finding per plugin per scan
- `CHECK(review_state IN ('pending', 'reviewed', 'completed', 'skipped'))`

**Relationships**: Has many `finding_affected_hosts`, `tool_executions`, and `workflow_executions`

---

### finding_affected_hosts

Host:port combinations per finding using normalized foreign keys.

| Column | Type | Description |
|---|---|---|
| `fah_id` | INTEGER | Primary key |
| `finding_id` | INTEGER | Foreign key to findings |
| `host_id` | INTEGER | Foreign key to normalized hosts table |
| `port_number` | INTEGER | Foreign key to ports table |
| `plugin_output` | TEXT | Plugin output from Nessus scanner |

**Note**: This table uses foreign keys to normalized `hosts` and `ports` tables rather than storing host addresses and port numbers directly. The host type (`ipv4`, `ipv6`, `hostname`) is stored in the `hosts` table.

**Foreign Keys**:
- `finding_id` → `findings.finding_id` (CASCADE DELETE)
- `host_id` → `hosts.host_id`
- `port_number` → `ports.port_number`

**Constraints**:
- `UNIQUE(finding_id, host_id, port_number)`

**Relationships**: Belongs to one `finding`, one `host`, and optionally one `port`

---

### sessions

Review session tracking.

| Column | Type | Description |
|---|---|---|
| `session_id` | INTEGER | Primary key |
| `scan_id` | INTEGER | Foreign key to scans |
| `session_start` | TIMESTAMP | Session start time |
| `session_end` | TIMESTAMP | Session end time |

**Note**: Session duration and statistics are computed via the `v_session_stats` view rather than stored as columns.

**Foreign Keys**:
- `scan_id` → `scans.scan_id` (CASCADE DELETE)

**Relationships**: Has many `tool_executions`

---

### tool_executions

Command execution tracking - one row per tool run.

| Column | Type | Description |
|---|---|---|
| `execution_id` | INTEGER | Primary key |
| `session_id` | INTEGER | Foreign key to sessions (NULL if outside session) |
| `finding_id` | INTEGER | Which plugin file triggered this |
| `tool_name` | TEXT | 'nmap', 'netexec', 'metasploit', 'custom' |
| `tool_protocol` | TEXT | For netexec: 'smb', 'ssh', 'rdp', etc. |
| `command_text` | TEXT | Full command as string |
| `command_args` | TEXT | JSON array of arguments |
| `executed_at` | TIMESTAMP | Execution timestamp |
| `exit_code` | INTEGER | Command exit code |
| `duration_seconds` | REAL | Execution duration |
| `host_count` | INTEGER | Number of hosts targeted |
| `sampled` | BOOLEAN | Was host list sampled (>5 hosts)? |
| `ports` | TEXT | Comma-separated port list |
| `used_sudo` | BOOLEAN | Was sudo used? |

**Foreign Keys**:
- `session_id` → `sessions.session_id` (SET NULL DELETE)
- `finding_id` → `findings.finding_id` (SET NULL DELETE)

**Relationships**: Has many `artifacts`

---

### artifacts

Generated output files - one row per artifact file.

| Column | Type | Description |
|---|---|---|
| `artifact_id` | INTEGER | Primary key |
| `execution_id` | INTEGER | Foreign key to tool_executions |
| `artifact_path` | TEXT | Absolute path (unique) |
| `artifact_type_id` | INTEGER | Foreign key to artifact_types lookup table |
| `file_size_bytes` | INTEGER | File size in bytes |
| `file_hash` | TEXT | SHA256 hash |
| `created_at` | TIMESTAMP | Creation timestamp |
| `last_accessed_at` | TIMESTAMP | Last access time |
| `metadata` | TEXT | JSON metadata (NSE scripts, UDP flag, etc.) |

**Note**: Artifact type names are accessed via the `v_artifacts_with_types` view by JOINing with `artifact_types`.

**Foreign Keys**:
- `execution_id` → `tool_executions.execution_id` (SET NULL DELETE)
- `artifact_type_id` → `artifact_types.artifact_type_id`

**Relationships**: Belongs to one `tool_execution` and one `artifact_type`

---

### workflow_executions

Custom workflow tracking - one row per workflow execution.

| Column | Type | Description |
|---|---|---|
| `workflow_execution_id` | INTEGER | Primary key |
| `finding_id` | INTEGER | Foreign key to findings |
| `workflow_name` | TEXT | Workflow identifier |
| `executed_at` | TIMESTAMP | Execution timestamp |
| `completed` | BOOLEAN | Completion status |
| `results` | TEXT | JSON results (step outcomes) |

**Foreign Keys**:
- `finding_id` → `findings.finding_id` (CASCADE DELETE)

**Relationships**: Belongs to one `finding`

---

## SQL Views (Computed Statistics)

Views provide computed aggregates without storing redundant data. All statistics are computed on-demand from normalized tables.

### v_finding_stats

Replaces `host_count` and `port_count` columns from `findings` table.

**Columns**:
- `finding_id`, `scan_id`, `plugin_id`, `review_state`, `reviewed_at`, `reviewed_by`, `review_notes`
- `host_count` - COUNT(DISTINCT host_id) from finding_affected_hosts
- `port_count` - COUNT(DISTINCT port_number) from finding_affected_hosts

**Usage**:
```sql
SELECT * FROM v_finding_stats WHERE finding_id = 123;
```

---

### v_session_stats

Replaces cached statistics columns from `sessions` table.

**Columns**:
- `session_id`, `scan_id`, `session_start`, `session_end`
- `duration_seconds` - Computed from start/end timestamps
- `files_reviewed` - COUNT files with review_state='reviewed'
- `files_completed` - COUNT files with review_state='completed'
- `files_skipped` - COUNT files with review_state='skipped'
- `tools_executed` - COUNT tool executions in session
- `cves_extracted` - COUNT plugins with non-NULL cves

**Usage**:
```sql
SELECT * FROM v_session_stats ORDER BY session_start DESC LIMIT 5;
```

---

### v_plugins_with_severity

Replaces `severity_label` column from `plugins` table - JOINs with `severity_levels`.

**Columns**:
- `plugin_id`, `plugin_name`, `severity_int`
- `severity_label` - From severity_levels table
- `color_hint` - From severity_levels table
- `has_metasploit`, `cvss3_score`, `cvss2_score`, `cves`, `metasploit_names`, `plugin_url`, `metadata_fetched_at`

**Usage**:
```sql
SELECT plugin_name, severity_label, cvss3_score
FROM v_plugins_with_severity
WHERE severity_int >= 3
ORDER BY severity_int DESC, cvss3_score DESC;
```

---

### v_host_findings

Cross-scan host analysis view.

**Columns**:
- `host_id`, `host_address`, `host_type`, `first_seen`, `last_seen`
- `scan_count` - Number of scans this host appeared in
- `finding_count` - Total findings across all scans
- `port_count` - Unique ports across all findings
- `max_severity` - Highest severity finding for this host

**Usage**:
```sql
-- Find hosts that appeared in multiple scans
SELECT host_address, scan_count, finding_count
FROM v_host_findings
WHERE scan_count > 1
ORDER BY scan_count DESC;
```

---

### v_artifacts_with_types

Replaces `artifact_type` TEXT column with JOIN to `artifact_types` table.

**Columns**:
- `artifact_id`, `execution_id`, `artifact_path`
- `artifact_type` - type_name from artifact_types table
- `file_extension`, `artifact_description` - From artifact_types table
- `file_size_bytes`, `file_hash`, `created_at`, `last_accessed_at`, `metadata`

**Usage**:
```sql
SELECT artifact_type, COUNT(*) as count, SUM(file_size_bytes) / 1024.0 / 1024.0 as total_mb
FROM v_artifacts_with_types
GROUP BY artifact_type
ORDER BY total_mb DESC;
```

---

## Query Examples

### Get Plugin File with Host/Port Counts

```sql
-- Old (v1.x): Query findings table directly
SELECT finding_id, scan_id, plugin_id, host_count, port_count
FROM findings
WHERE finding_id = 123;

-- Query view for computed host/port counts
SELECT finding_id, scan_id, plugin_id, host_count, port_count
FROM v_finding_stats
WHERE finding_id = 123;
```

---

### Get Plugin with Severity Label

```sql
-- Old (v1.x): Query plugin table directly
SELECT plugin_id, plugin_name, severity_label, cvss3_score
FROM plugins
WHERE plugin_id = 57608;

-- Query view with severity labels from lookup table
SELECT plugin_id, plugin_name, severity_label, cvss3_score
FROM v_plugins_with_severity
WHERE plugin_id = 57608;
```

---

### Find All Findings for a Specific Host Across All Scans

Enabled by the normalized hosts table:

```sql
SELECT
    h.host_address,
    s.scan_name,
    s.created_at as scan_date,
    p.plugin_name,
    sl.severity_label,
    f.review_state
FROM hosts h
JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
JOIN findings f ON fah.finding_id = f.finding_id
JOIN plugins p ON f.plugin_id = p.plugin_id
JOIN severity_levels sl ON p.severity_int = sl.severity_int
JOIN scans s ON f.scan_id = s.scan_id
WHERE h.host_address = '192.168.1.10'
ORDER BY s.created_at DESC, sl.severity_order DESC;
```

---

### Get Hosts that Appeared in Multiple Scans

Using the `v_host_findings` view:

```sql
SELECT
    host_address,
    host_type,
    scan_count,
    finding_count,
    port_count,
    first_seen,
    last_seen
FROM v_host_findings
WHERE scan_count > 1
ORDER BY scan_count DESC, finding_count DESC;
```

---

### Review Progress Across All Scans

```sql
SELECT
    s.scan_name,
    COUNT(*) as total_files,
    SUM(CASE WHEN f.review_state = 'completed' THEN 1 ELSE 0 END) as completed,
    SUM(CASE WHEN f.review_state = 'reviewed' THEN 1 ELSE 0 END) as reviewed,
    SUM(CASE WHEN f.review_state = 'pending' THEN 1 ELSE 0 END) as pending,
    ROUND(100.0 * SUM(CASE WHEN f.review_state = 'completed' THEN 1 ELSE 0 END) / COUNT(*), 1) as completion_pct
FROM scans s
JOIN findings f ON f.scan_id = s.scan_id
GROUP BY s.scan_name
ORDER BY completion_pct DESC;
```

---

### Find Critical Plugins with Metasploit Modules

```sql
SELECT
    p.plugin_id,
    p.plugin_name,
    sl.severity_label,
    p.cvss3_score,
    p.metasploit_names,
    COUNT(DISTINCT f.scan_id) as scan_count,
    COUNT(DISTINCT h.host_address) as unique_hosts
FROM plugins p
JOIN severity_levels sl ON p.severity_int = sl.severity_int
JOIN findings f ON f.plugin_id = p.plugin_id
JOIN finding_affected_hosts fah ON fah.finding_id = f.finding_id
JOIN hosts h ON fah.host_id = h.host_id
WHERE p.severity_int = 4  -- Critical
  AND p.has_metasploit = 1
GROUP BY p.plugin_id, p.plugin_name, sl.severity_label, p.cvss3_score, p.metasploit_names
ORDER BY p.cvss3_score DESC, unique_hosts DESC;
```

---

### Session Statistics

```sql
-- Get session statistics with computed values
SELECT
    session_id,
    session_start,
    session_end,
    ROUND(duration_seconds / 60.0, 1) as duration_minutes,
    files_completed,
    files_reviewed,
    files_skipped,
    tools_executed,
    cves_extracted
FROM v_session_stats
ORDER BY session_start DESC
LIMIT 10;
```

---

### Artifact Storage by Type

```sql
SELECT
    artifact_type,
    COUNT(*) as file_count,
    SUM(file_size_bytes) / 1024.0 / 1024.0 as total_mb,
    ROUND(AVG(file_size_bytes) / 1024.0, 1) as avg_kb
FROM v_artifacts_with_types
GROUP BY artifact_type
ORDER BY total_mb DESC;
```

---

## Cross-Scan Tracking

The normalized schema enables powerful cross-scan queries:

### Track Host Appearance History

```sql
-- When did each host first and last appear?
SELECT
    h.host_address,
    h.first_seen,
    h.last_seen,
    julianday(h.last_seen) - julianday(h.first_seen) as days_tracked,
    v.scan_count,
    v.finding_count
FROM hosts h
JOIN v_host_findings v ON h.host_id = v.host_id
ORDER BY days_tracked DESC;
```

---

### Compare Host Findings Between Two Scans

```sql
SELECT
    h.host_address,
    s1_findings.plugin_count as scan1_plugins,
    s2_findings.plugin_count as scan2_plugins,
    CASE
        WHEN s1_findings.plugin_count > s2_findings.plugin_count THEN 'Improved'
        WHEN s1_findings.plugin_count < s2_findings.plugin_count THEN 'Worsened'
        ELSE 'Same'
    END as trend
FROM hosts h
LEFT JOIN (
    SELECT fah.host_id, COUNT(DISTINCT f.plugin_id) as plugin_count
    FROM finding_affected_hosts fah
    JOIN findings f ON fah.finding_id = f.finding_id
    JOIN scans s ON f.scan_id = s.scan_id
    WHERE s.scan_name = 'Scan1'
    GROUP BY fah.host_id
) s1_findings ON h.host_id = s1_findings.host_id
LEFT JOIN (
    SELECT fah.host_id, COUNT(DISTINCT f.plugin_id) as plugin_count
    FROM finding_affected_hosts fah
    JOIN findings f ON fah.finding_id = f.finding_id
    JOIN scans s ON f.scan_id = s.scan_id
    WHERE s.scan_name = 'Scan2'
    GROUP BY fah.host_id
) s2_findings ON h.host_id = s2_findings.host_id
WHERE s1_findings.plugin_count IS NOT NULL
   OR s2_findings.plugin_count IS NOT NULL
ORDER BY ABS(COALESCE(s1_findings.plugin_count, 0) - COALESCE(s2_findings.plugin_count, 0)) DESC;
```

---

### Find New Hosts in Latest Scan

```sql
-- Hosts that appear in latest scan but not in previous scans
SELECT
    h.host_address,
    h.host_type,
    COUNT(DISTINCT f.plugin_id) as finding_count,
    MAX(p.severity_int) as max_severity
FROM hosts h
JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
JOIN findings f ON fah.finding_id = f.finding_id
JOIN plugins p ON f.plugin_id = p.plugin_id
WHERE f.scan_id = (SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 1)
  AND h.host_id NOT IN (
      SELECT DISTINCT fah2.host_id
      FROM finding_affected_hosts fah2
      JOIN findings f2 ON fah2.finding_id = f2.finding_id
      WHERE f2.scan_id != (SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 1)
  )
GROUP BY h.host_id, h.host_address, h.host_type
ORDER BY max_severity DESC, finding_count DESC;
```

---

## Schema Reference

Full schema available in [`../schema.sql`](../schema.sql).

### Database Initialization

The database is initialized automatically on first use. Schema creation is handled by `cerno_pkg/database.py:initialize_database()`.

**Key Points**:
- Schema version: 1 (single-version, no migration system)
- All tables created with `CREATE TABLE IF NOT EXISTS` for idempotency
- Foundation tables pre-populated automatically
- Views created after tables
- Foreign key constraints enforced on all connections

### PRAGMA Settings

Applied at connection time for optimal performance:

```sql
PRAGMA journal_mode=WAL;        -- Write-Ahead Logging for concurrency
PRAGMA foreign_keys=ON;         -- Enable referential integrity
PRAGMA synchronous=NORMAL;      -- Balance safety and performance
PRAGMA temp_store=MEMORY;       -- Keep temp tables in memory
PRAGMA cache_size=-64000;       -- 64MB cache
```

### Foreign Key Relationships

```
scans
  ├── findings (scan_id) - CASCADE DELETE
  └── sessions (scan_id) - CASCADE DELETE

plugins
  └── findings (plugin_id) - RESTRICT DELETE

severity_levels
  └── plugins (severity_int) - RESTRICT DELETE

hosts
  └── finding_affected_hosts (host_id) - RESTRICT DELETE

ports
  └── finding_affected_hosts (port_number) - RESTRICT DELETE

findings
  ├── finding_affected_hosts (finding_id) - CASCADE DELETE
  ├── tool_executions (finding_id) - SET NULL DELETE
  └── workflow_executions (finding_id) - CASCADE DELETE

sessions
  └── tool_executions (session_id) - SET NULL DELETE

tool_executions
  └── artifacts (execution_id) - SET NULL DELETE

artifact_types
  └── artifacts (artifact_type_id) - RESTRICT DELETE
```

**Cascade Rules**:
- Deleting a scan removes all findings, sessions, and dependent records
- Deleting a finding removes all finding_affected_hosts and workflow_executions
- Deleting a session or tool_execution sets foreign keys to NULL (preserves artifacts)
- Cannot delete severity_levels, hosts, ports, or artifact_types if referenced

---

## Database Maintenance

### Direct Database Access

```bash
# Open database in sqlite3 CLI
sqlite3 ~/.cerno/cerno.db

# Run a query
sqlite3 ~/.cerno/cerno.db "SELECT * FROM v_host_findings LIMIT 10;"

# Export to CSV
sqlite3 -csv ~/.cerno/cerno.db "SELECT * FROM v_session_stats;" > sessions.csv
```

### Health Checks

```bash
# Check database integrity
sqlite3 ~/.cerno/cerno.db "PRAGMA integrity_check;"

# Optimize database (reclaim space)
sqlite3 ~/.cerno/cerno.db "VACUUM;"

# Database statistics
sqlite3 ~/.cerno/cerno.db "
  SELECT
    (page_count * page_size) / 1024.0 / 1024.0 as size_mb
  FROM (
    SELECT (SELECT * FROM pragma_page_count) as page_count,
           (SELECT * FROM pragma_page_size) as page_size
  );
"
```

### Backup Database

```bash
# Simple copy
cp ~/.cerno/cerno.db ~/.cerno/cerno.db.backup

# SQLite backup command (safer during active use)
sqlite3 ~/.cerno/cerno.db ".backup ~/.cerno/cerno.db.backup"
```

---

## Future Enhancements

Planned database features:

- **Enhanced cross-scan analytics**: Trend analysis, risk scoring over time
- **Reverse DNS resolution**: Automatically populate `hosts.reverse_dns`
- **Port service detection**: Populate `ports.service_name` from nmap results
- **Audit triggers**: Automatically track changes to critical tables
- **Export utilities**: Generate reports from database queries
- **Web UI**: Database-backed web interface for team collaboration

---

**Last Updated**: 2026-01-09 (v1.0.0 - Cerno Initial Release)
**Maintained By**: Ridgeback InfoSec, LLC
**Schema Version**: 1

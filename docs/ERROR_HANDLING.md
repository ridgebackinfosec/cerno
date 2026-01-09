# Error Handling Standards

This document defines the standardized error handling patterns for the cerno codebase.

## Principles

1. **User-Facing Errors**: Always provide actionable, user-friendly error messages
2. **Logging**: Log detailed technical errors for debugging
3. **Fail Gracefully**: Continue operation when possible, fail fast when critical
4. **Consistent Patterns**: Use the same error handling approach for similar error types

---

## Error Categories

### 1. Network Errors

**Context**: Fetching data from external sources (Tenable plugin pages, web resources)

**Pattern**:
```python
try:
    response = fetch_data(url)
except requests.RequestException as e:
    log_error(f"Network request failed for {url}: {e}")
    warn(f"Failed to fetch data from {url}. Check network connection.")
    return None  # Or appropriate fallback value
except requests.Timeout:
    log_error(f"Request timed out for {url}")
    warn(f"Request timed out. Server may be slow or unreachable.")
    return None
```

**Key Points**:
- Log full exception details (`log_error`)
- Display user-friendly message (`warn()`)
- Return `None` or fallback value (don't raise unless critical)
- Distinguish timeout from general network errors

**Examples**:
- CVE fetching from Tenable
- Web scraping operations
- API requests

---

### 2. Database Errors

**Context**: SQLite operations, transactions, schema issues

**Pattern**:
```python
try:
    with db_transaction(conn) as c:
        c.execute(query, params)
        conn.commit()
except sqlite3.IntegrityError as e:
    log_error(f"Database integrity violation: {e}")
    raise  # Re-raise - data corruption is critical
except sqlite3.OperationalError as e:
    log_error(f"Database operation failed: {e}")
    warn("Database operation failed. Database may be locked or corrupted.")
    raise  # Re-raise - database errors are critical
except Exception as e:
    log_error(f"Unexpected database error: {e}")
    raise
```

**Key Points**:
- **Always re-raise** database errors (critical for data integrity)
- Use `db_transaction` context manager (auto-rollback)
- Log before re-raising
- Distinguish integrity errors from operational errors

**Examples**:
- Plugin/scan save operations
- Tool execution logging
- Session management

---

### 3. Parsing Errors

**Context**: Parsing files, extracting data from structured/unstructured text

**Pattern**:
```python
try:
    data = parse_file(file_path)
except ValueError as e:
    log_error(f"Failed to parse {file_path}: {e}")
    warn(f"Skipping {file_path.name} - invalid format")
    return []  # Return empty list, continue processing
except FileNotFoundError:
    log_error(f"File not found: {file_path}")
    warn(f"File {file_path.name} not found")
    return []
except Exception as e:
    log_error(f"Unexpected error parsing {file_path}: {e}")
    warn(f"Failed to parse {file_path.name}")
    return []
```

**Key Points**:
- **Don't raise** - continue processing other files
- Log error with file context
- Return empty/default value
- Specific exceptions for common cases (FileNotFoundError, ValueError)

**Examples**:
- Nessus XML parsing
- Plugin file parsing (host:port extraction)
- Configuration file parsing

---

### 4. Subprocess Errors

**Context**: External command execution (nmap, netexec, etc.)

**Pattern**:
```python
try:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False  # Don't raise on non-zero exit
    )

    if result.returncode != 0:
        log_error(f"Command failed with exit code {result.returncode}: {command}")
        log_error(f"stderr: {result.stderr}")
        warn(f"Command failed: {' '.join(command)}")

    return result

except subprocess.TimeoutExpired as e:
    log_error(f"Command timed out after {timeout}s: {command}")
    warn(f"Command timed out after {timeout} seconds")
    return None
except FileNotFoundError:
    log_error(f"Command not found: {command[0]}")
    err(f"Command '{command[0]}' not found. Ensure it's installed and on PATH.")
    sys.exit(1)  # Critical - can't continue without required tool
except Exception as e:
    log_error(f"Unexpected error running command: {e}")
    warn(f"Failed to execute command")
    return None
```

**Key Points**:
- Use `check=False` to handle exit codes manually
- Log both exit code and stderr
- Timeout vs NotFound vs general errors
- Exit on missing critical tools

**Examples**:
- nmap scans
- netexec execution
- git operations

---

### 5. File System Errors

**Context**: File/directory operations

**Pattern**:
```python
try:
    path.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        f.write(data)
except PermissionError as e:
    log_error(f"Permission denied: {file_path}: {e}")
    err(f"Permission denied: {file_path}")
    err("Try running with appropriate permissions or check file ownership.")
    sys.exit(1)
except OSError as e:
    log_error(f"File system error: {e}")
    warn(f"Failed to write to {file_path}")
    return False
```

**Key Points**:
- Exit on permission errors (can't recover)
- Log OS-level errors
- Provide guidance for permission issues

**Examples**:
- Creating scan directories
- Writing results files
- File renames for review state

---

## Helper Functions

### Logging Helpers

```python
from .logging_setup import log_error, log_info, log_warning

# ERROR: Technical details for debugging
log_error(f"Failed to fetch plugin {plugin_id}: {exception}")

# INFO: Normal operations
log_info(f"Successfully imported {file_count} plugin files")

# WARNING: Unexpected but non-critical
log_warning(f"Plugin {plugin_id} missing metadata, using defaults")
```

### User-Facing Helpers

```python
from .ansi import err, warn, info, ok

# ERROR: Critical failure, usually followed by exit
err("Required command 'nmap' not found on PATH")
sys.exit(1)

# WARN: Problem occurred but continuing
warn("Failed to fetch CVEs. Continuing without CVE data.")

# INFO: Normal status message
info("Fetching plugin page from Tenable...")

# OK: Success confirmation
ok("Successfully imported scan")
```

---

## Anti-Patterns to Avoid

❌ **Silent Failures**:
```python
# BAD
try:
    data = fetch_data()
except Exception:
    pass  # Silent failure - no log, no user message
```

✅ **Proper Handling**:
```python
# GOOD
try:
    data = fetch_data()
except Exception as e:
    log_error(f"Failed to fetch data: {e}")
    warn("Failed to fetch data. Continuing with cached version.")
    data = get_cached_data()
```

---

❌ **Catch-All Without Re-raise**:
```python
# BAD - masks database errors
try:
    plugin.save(conn)
except Exception:
    log_error("Save failed")
    return None  # Should re-raise for DB errors!
```

✅ **Appropriate Exception Handling**:
```python
# GOOD - re-raises critical errors
try:
    plugin.save(conn)
except sqlite3.Error as e:
    log_error(f"Database error: {e}")
    raise  # Re-raise - DB errors are critical
```

---

❌ **Generic Error Messages**:
```python
# BAD
warn("Operation failed")
```

✅ **Actionable Messages**:
```python
# GOOD
warn("Failed to fetch CVEs for plugin 11356. Check network connection or try again later.")
```

---

## Testing Error Handling

All error handling paths should be tested:

```python
def test_network_error_handling(mock_fetch):
    """Test graceful handling of network errors."""
    mock_fetch.side_effect = requests.RequestException("Connection refused")

    result = fetch_cves(plugin_id=12345)

    assert result is None  # Graceful fallback
    # Verify logging occurred
```

---

## Migration Checklist

When updating code to follow these standards:

1. ✅ Identify all `try/except` blocks
2. ✅ Categorize exception type (network, database, parsing, etc.)
3. ✅ Apply appropriate pattern from this document
4. ✅ Add logging (`log_error`) with context
5. ✅ Add user-facing message (`warn`/`err`) if appropriate
6. ✅ Return appropriate value or re-raise based on criticality
7. ✅ Add test for error path

---

## Summary Table

| Error Type | Log Level | User Message | Action | Re-raise? |
|------------|-----------|--------------|--------|-----------|
| Network | ERROR | warn() | Return None | No |
| Database | ERROR | warn() | - | **Yes** |
| Parsing | ERROR | warn() | Return default | No |
| Subprocess Timeout | ERROR | warn() | Return None | No |
| Subprocess NotFound | ERROR | err() | Exit | N/A |
| Permission | ERROR | err() | Exit | N/A |
| File System | ERROR | warn() | Return False | No |

---

**Last Updated**: 2025-01-13
**Applies To**: cerno v2.0+

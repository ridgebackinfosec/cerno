# Testing Guide for Cerno

This document explains how to run and write tests for the Cerno project.

## Test Structure

```
tests/
├── conftest.py                 # Shared fixtures; autouse isolation of config path + caches
├── fixtures/
│   ├── GOAD.nessus             # Full real-world scan (74 plugins, 755 hosts)
│   ├── minimal.nessus          # Minimal scan (3 plugins, 3 hosts)
│   ├── nmap/                   # nmap XML for ingest tests (MS17-010, no hosts up)
│   └── nxc/                    # NetExec protocol databases (smb, ldap, winrm, …)
└── test_*.py                   # 36 test modules, roughly one per cerno_pkg module
```

The modules group roughly as:

| Area | Test files |
|---|---|
| Core data | `test_database.py`, `test_models.py`, `test_parsing.py`, `test_nessus_import.py`, `test_cross_scan.py`, `test_analysis.py`, `test_scan_list.py` |
| Review TUI | `test_render.py`, `test_fs.py`, `test_session.py`, `test_review_states.py`, `test_multi_scan_review.py`, `test_color_scheme.py`, `test_demo_command.py` |
| Tools & execution | `test_ops.py`, `test_tool_registry.py`, `test_exec_chain.py`, `test_workflow_mapper.py`, `test_workflow_prep.py`, `test_nxc_db.py` |
| Verification loop | `test_nmap_parse.py`, `test_ingest.py`, `test_verdicts.py`, `test_query.py`, `test_batch.py`, `test_jobs.py`, `test_workflow_contrib.py` |
| Credentials | `test_creds.py`, `test_cred_injection.py` |
| MCP server | `test_mcp_server.py`, `test_mcp_contract.py` (frozen tool/resource/prompt inventory), `test_mcp_config.py` (every config key classified for MCP) |
| Config & misc | `test_config.py`, `test_claude_assistant.py`, `test_version.py` |

`test_database.py` also checks that the reference `schema.sql` defines the same
tables, views and indexes as `cerno_pkg/database.py`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the TUI ↔ MCP contract tests.

## Running Tests

### Install Test Dependencies

```bash
pip install -e ".[dev]"
```

This installs (among others):
- pytest
- pytest-cov (coverage reporting)
- pytest-mock (mocking utilities)
- pytest-timeout (prevent hanging tests)

### Run All Tests

```bash
pytest
```

`pyproject.toml` already adds coverage (`--cov=cerno_pkg` with terminal, HTML and
XML reports), `--strict-markers` and a 300-second per-test timeout to every run.
Add `--no-cov` for a faster run when you don't need the report.

### Run with Coverage

Coverage is on by default (see above). The reports land in `htmlcov/` and
`coverage.xml`:

View HTML coverage report:
```bash
# On Linux/Mac
open htmlcov/index.html

# On Windows
start htmlcov/index.html
```

### Run Specific Test Files

```bash
pytest tests/test_parsing.py                # Just parsing tests
pytest tests/test_database.py              # Just database tests
pytest tests/test_models.py                # Just model tests
```

### Run Tests by Marker

```bash
pytest -m unit                              # Only unit tests (fast)
pytest -m integration                      # Only integration tests
pytest -m "not slow"                       # Skip slow tests
```

### Run Tests in Parallel

```bash
pip install pytest-xdist
pytest -n auto                             # Use all CPU cores
```

### Verbose Output

```bash
pytest -v                                   # Verbose test names
pytest -vv                                  # Even more verbose
pytest -s                                   # Show print statements
```

### Run Specific Test

```bash
pytest tests/test_parsing.py::TestSplitHostPort::test_ipv4_with_port
pytest tests/test_database.py::TestDatabaseTransaction::test_transaction_commits_on_success
```

## Test Markers

Tests are marked with the following markers:

- `@pytest.mark.unit` - Fast, isolated unit tests
- `@pytest.mark.integration` - Tests involving database or filesystem
- `@pytest.mark.slow` - Tests that take longer (e.g., GOAD.nessus parsing)

## Available Fixtures

### Shared (`tests/conftest.py`)

- `temp_db` - In-memory SQLite database with the full schema initialized
- `temp_dir` - Temporary directory (automatically cleaned up)
- `goad_nessus_fixture` - Path to the full GOAD scan (74 plugins, 755 hosts)
- `sample_nessus_xml` - Generated minimal Nessus XML in `temp_dir`
- `sample_hosts_list` - List of mixed host formats (IPv4, IPv6, hostnames)
- `reset_environment` (autouse) - Points `config.get_config_path()` at a temp
  file, clears legacy env vars and resets cached config, so a test never reads
  or writes your real `~/.cerno/config.yaml`

### Module-local

- `minimal_nessus_fixture` - Path to `fixtures/minimal.nessus` (3 plugins, 3
  hosts), defined in `tests/test_nessus_import.py`
- Many modules define their own seeded-database fixtures (e.g. `seeded` in
  `tests/test_mcp_server.py`)

## Writing New Tests

### Test File Naming

- Test files: `test_<module>.py`
- Test classes: `class Test<FeatureName>`
- Test functions: `def test_<what_it_tests>()`

### Example Unit Test

```python
import pytest
from cerno_pkg.parsing import split_host_port

def test_ipv4_with_port():
    """Test IPv4 address with port."""
    host, port = split_host_port("192.168.1.1:80")
    assert host == "192.168.1.1"
    assert port == "80"  # ports are returned as strings
```

### Example Integration Test

```python
import pytest
from cerno_pkg.models import Scan

@pytest.mark.integration
def test_scan_save_creates_record(temp_db):
    """Test saving a new scan to database."""
    scan = Scan(
        scan_name="test_scan",
        export_root="/tmp"
    )
    scan_id = scan.save(temp_db)

    assert scan_id is not None
    assert scan_id > 0
```

### Example Parametrized Test

```python
import pytest
from cerno_pkg.parsing import split_host_port

@pytest.mark.parametrize(
    "input_str,expected_host,expected_port",
    [
        ("192.168.1.1:80", "192.168.1.1", "80"),
        ("10.0.0.1", "10.0.0.1", None),
        ("[::1]:8080", "::1", "8080"),
    ],
)
def test_split_host_port_parametrized(input_str, expected_host, expected_port):
    """Parametrized test for split_host_port."""
    host, port = split_host_port(input_str)
    assert host == expected_host
    assert port == expected_port
```

## Continuous Integration

Tests run automatically on GitHub Actions for:
- Python 3.11, 3.12 and 3.13 (3.13 is allowed to fail)
- Ubuntu, Windows, and macOS
- Every push to `main` or `develop`
- Every pull request targeting `main` or `develop`

See `.github/workflows/test.yml` for configuration.

## Coverage Goals

- **Overall target**: 85% coverage
- **Critical modules**: 90%+ coverage
  - `database.py` - Database operations
  - `models.py` - ORM models
  - `parsing.py` - Host/port parsing
  - `nessus_import.py` - XML parsing and import

## Common Issues

### ImportError in Tests

If you see `ImportError: cannot import name 'X'`:
```bash
pip install -e .  # Reinstall package in development mode
```

### Database Locked Errors

If you see "database is locked":
- Tests use in-memory databases by default (no locking)
- If testing with file-based DB, ensure only one connection at a time

### Fixture Not Found

If you see `fixture 'X' not found`:
- Check `tests/conftest.py` for available fixtures
- Ensure pytest is discovering conftest.py (run `pytest --fixtures`)

### Test File Not Discovered

If pytest doesn't find your test:
- Ensure filename starts with `test_`
- Ensure function name starts with `test_`
- Check it's in the `tests/` directory
- Run `pytest --collect-only` to see what pytest finds

## Debugging Tests

### Run with PDB

```bash
pytest --pdb                                # Drop into debugger on failure
pytest --pdb --maxfail=1                   # Stop after first failure
```

### Show Locals on Failure

```bash
pytest --showlocals                        # Show local variables
pytest -l                                  # Short form
```

### Capture Control

```bash
pytest -s                                  # Don't capture stdout
pytest --capture=no                        # Same as -s
```

## Performance

Current test suite performance targets:
- Unit tests: < 0.1s each
- Integration tests: < 1s each
- Full test suite: < 30s total

Run with timing:
```bash
pytest --durations=10                      # Show 10 slowest tests
pytest --durations=0                       # Show all test durations
```

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)

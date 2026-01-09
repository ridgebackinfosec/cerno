# Testing Guide for Cerno

This document explains how to run and write tests for the Cerno project.

## Test Structure

```
tests/
├── conftest.py                    # Shared fixtures and pytest configuration
├── fixtures/
│   ├── GOAD.nessus               # Full real-world scan (51K lines)
│   └── minimal.nessus            # Minimal test scan (3 plugins, 3 hosts)
├── test_parsing.py               # Host/port parsing functions
├── test_database.py              # Database operations and transactions
├── test_models.py                # ORM model CRUD operations
└── test_nessus_export.py         # Nessus XML parsing and export
```

## Running Tests

### Install Test Dependencies

```bash
pip install -e ".[dev]"
```

This installs:
- pytest
- pytest-cov (coverage reporting)
- pytest-mock (mocking utilities)
- pytest-timeout (prevent hanging tests)

### Run All Tests

```bash
pytest
```

### Run with Coverage

```bash
pytest --cov=cerno_pkg --cov-report=term-missing --cov-report=html
```

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
pytest tests/test_database.py::test_transaction_commits_on_success
```

## Test Markers

Tests are marked with the following markers:

- `@pytest.mark.unit` - Fast, isolated unit tests
- `@pytest.mark.integration` - Tests involving database or filesystem
- `@pytest.mark.slow` - Tests that take longer (e.g., GOAD.nessus parsing)

## Available Fixtures

### Database Fixtures

- `temp_db` - In-memory SQLite database with schema initialized
- Perfect for testing database operations without file I/O

### Filesystem Fixtures

- `temp_dir` - Temporary directory (automatically cleaned up)
- `sample_scan_dir` - Scan directory structure (Critical/High/Medium/Low/Info)
- `sample_plugin_file` - Pre-created plugin file with host entries

### Nessus Fixtures

- `minimal_nessus_fixture` - Minimal Nessus XML (3 plugins, 3 hosts)
- `goad_nessus_fixture` - Full GOAD scan (74 plugins, 755 hosts)
- `sample_nessus_xml` - Generated minimal XML for basic tests

### Data Fixtures

- `sample_hosts_list` - List of mixed host formats (IPv4, IPv6, hostnames)
- `mock_session_state` - Mock session state dictionary

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
    assert port == 80
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
        ("192.168.1.1:80", "192.168.1.1", 80),
        ("10.0.0.1", "10.0.0.1", None),
        ("[::1]:8080", "::1", 8080),
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
- Python 3.11 and 3.12
- Ubuntu, Windows, and macOS
- Every push to `main` or `develop`
- Every pull request

See `.github/workflows/test.yml` for configuration.

## Coverage Goals

- **Overall target**: 85% coverage
- **Critical modules**: 90%+ coverage
  - `database.py` - Database operations
  - `models.py` - ORM models
  - `parsing.py` - Host/port parsing
  - `nessus_export.py` - XML parsing and export

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

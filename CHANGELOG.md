# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-01-09

### Added
- Automated GitHub release workflow triggered by version changes in `pyproject.toml`
- Changelog extraction script (`scripts/extract_changelog.py`) for generating release notes
- GitHub Actions workflow (`.github/workflows/release.yml`) that:
  - Detects version changes on push to main (PR merges or direct commits)
  - Validates semantic versioning format
  - Creates annotated git tags automatically
  - Generates GitHub Releases marked as "latest"
  - Extracts release notes from CHANGELOG.md
  - Builds and attaches distribution artifacts (wheel and sdist)

### Changed
- Updated README.md with new "Releases" section explaining automated release process
- Expanded CLAUDE.md "Version Management" section with detailed workflow documentation

## [1.0.1] - 2026-01-09

### Documentation
- Added "About the Name" section to README explaining Cerno etymology and pronunciation
- Includes Latin origin (*cernō* - to discern, distinguish, perceive)
- Provides pronunciation guide (KEHR-noh / IPA: [ˈkɛr.noː]) with audio sample link
- Explains connection between name meaning and tool purpose

## [1.0.0] - 2026-01-09

### Initial Release
- First public release of Cerno (from Latin "cernō" - to discern, perceive, understand)
- Modern CLI for Nessus findings review and security tool orchestration
- SQLite-backed persistence with normalized database schema
- Rich TUI for interactive review with keyboard navigation
- Integration with nmap, NetExec, and Metasploit
- Workflow orchestration and session tracking
- Cross-scan host analysis capabilities
- Configuration management via `~/.cerno/config.yaml`
- Comprehensive test suite with 85%+ coverage

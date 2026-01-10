# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-01-09

### Changed
- Enhanced Version Increment SOP in CLAUDE.md with mandatory incremental changelog updates and user confirmation workflow
  - Added "Incremental Changelog Updates" section requiring [Unreleased] updates after all code changes
  - Updated "Version Increment SOP" with 4-phase process: gather changes, present for approval, update atomically, validate
  - Modified "Documentation" principle to mandate [Unreleased] section updates for user-visible changes
  - Version increments now require reviewing git history, [Unreleased] section, and user confirmation before proceeding

### Documentation
- Integrated pyright for type checking in development workflow (CLAUDE.md)
  - Added pyright to dev dependencies in pyproject.toml
  - Documented dual type checking philosophy (mypy + pyright)
  - Added pyrightconfig.json configuration reference
- Added comprehensive version increment SOP to CLAUDE.md
  - Documents 4-phase process for version bumps with user confirmation
  - Includes changelog gathering from multiple sources
  - Ensures atomic updates to pyproject.toml and CHANGELOG.md

## [1.1.0] - 2026-01-10

### Added
- **Terminal responsiveness** with adaptive layouts for different screen widths
  - Terminal width detection utility (`ansi.py:get_terminal_width()`) with graceful fallback to 80 chars
  - Responsive action footer: 2-column grid for wide terminals (≥100 chars), single-column for narrow (<100 chars)
  - Responsive status line: adapts layout based on width (single-line ≥120, two-line 80-119, multi-line <80)
- **Smart CVE format selection** with preview and auto-defaults
  - Shows "Found N unique CVE(s) across M finding(s)" preview before format selection
  - Auto-selects combined format for 1-2 findings, separated format for 3+ findings
  - Manual override still available
- **Group filter descriptions** for better context
  - Enhanced tuple from `(index, plugin_ids)` to `(index, plugin_ids, description)`
  - Status line now shows "Group #1: Identical host:port combinations (N)" instead of cryptic "Group #1 (N)"
- **Page size configuration support** via `config.yaml`
  - Users can set `default_page_size: 20` to override auto-detection
  - Falls back to 12 if terminal height detection fails (logs debug hint)
- **Comparison groups pager** for large result sets
  - Groups with >8 findings show "... (+N more - press [D] to view details)"
  - [D] option displays full list in pager without truncation

### Changed
- **Streamlined file detail view workflow** (reduced from 4 steps to 1-2 steps)
  - View action now defaults to grouped format immediately (no format prompt)
  - Post-view menu offers Copy/Change format/Back options
  - Menu shows "[V] View host(s) (grouped)" to indicate default format
- **Improved visual hierarchy** for Metasploit indicators
  - Moved ⚡ indicator from first content line to panel subtitle
  - Cleaner separation between metadata and plugin data
- **Clarified completed findings section** to reduce confusion
  - Renamed from "Reviewed findings (read-only)" to "Completed Findings (Undo Available)"
  - Updated action from "Undo review-complete" to "Undo completion"
  - Enhanced help text explaining management view purpose

### Documentation
- Added "Terminal Responsiveness" section to CLAUDE.md documenting all UI improvements
- Documented group filter tuple enhancement and backward compatibility approach
- Added page size configuration examples

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

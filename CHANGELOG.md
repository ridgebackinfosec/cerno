# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2] - 2026-01-11

### Fixed
- Fixed workflow count display to show distinct workflows instead of total plugin ID entries (workflow_mapper.py:count())

### Changed
- Improved keybinding mnemonics: Sort now uses [S] instead of [O], Overlapping uses [O] instead of [I] (render.py, tui.py)

## [1.2.1] - 2026-01-11

### Fixed
- Fixed jarring yellow-on-red filter indicators - changed to readable bold cyan/yellow text (cerno.py)

## [1.2.0] - 2026-01-10

### Added
- Added startup help hint on first review showing "Press [?] for help" banner (cerno.py:browse_file_list())
- Added active filter visual indicators with bold yellow-on-red badges in status line (cerno.py)
- Added severity column to all finding list tables (render.py:render_finding_list_table())
- Added workflow availability badges to finding preview panels (render.py:display_finding_preview())
- Added next sort mode indicator in status line showing upcoming sort order (cerno.py)
- Added CVE distribution preview before format selection showing count per finding (render.py:display_bulk_cve_results())
- Added pre-flight execution summary showing targets, scripts, and output directory (tools.py:command_review_menu())
- Added post-execution summary panel with duration, exit code, files generated, and next steps (tools.py:run_tool_orchestration())
- Added consolidated nmap configuration screen combining NSE profile, custom scripts, and UDP options (tools.py:configure_nmap_options())
- Added port distribution to finding preview showing host count per port (models.py:get_port_distribution(), render.py:display_finding_preview())
- Added session time indicator to status line with elapsed time and review counts (cerno.py:browse_file_list())
- Added Metasploit module names to preview panel subtitles (render.py:display_finding_preview())
- Added `cerno workflow list` CLI command to display all available workflows with descriptions (cerno.py:workflow_list())

### Changed
- Changed bulk mark confirmation from typing "mark" to standard Y/N confirmation (tui.py)
- Improved "Superset" terminology to "Overlapping Findings" throughout UI (render.py, analysis.py, tui.py)
- Enhanced group filter descriptions to include context (e.g., "Group #1: Identical host:port combinations")
- Streamlined nmap workflow to use single configuration screen instead of 3 sequential prompts
- Enhanced filter prompts with inline examples (e.g., 'apache', 'ssl', 'windows') for better discoverability (tui.py)
- Improved large group pagination indicator with bold yellow message "Showing 8 of X findings - Press [D] to view all" (render.py)
- Changed severity table unreviewed count color from green/yellow/red to neutral cyan for progress tracking (render.py:unreviewed_cell())
- Enhanced workflow display with prominent "Press Enter to continue" hint in bold yellow (fs.py:display_workflow())
- Added terminal width warning on first review for terminals <80 chars (cerno.py:browse_file_list())
- Added confirmation feedback when clearing filters with [C] key (tui.py)

### Fixed
- Fixed ExecutionMetadata type error in post-execution summary (use attribute access instead of dict access)

## [1.1.2] - 2026-01-10

### Fixed
- Resolved all 224 Pylance/Pyright type checking warnings (reduced from 224 to 0)
  - Fixed 20 unused variable warnings by renaming to `_` prefix convention
  - Fixed 5 private usage warnings by making tool workflow builders semi-public
  - Fixed 140 unused import warnings in `cerno_pkg/__init__.py` by adding explicit `__all__` list
  - Removed 56 unused imports from `cerno.py` after refactoring
  - Added type ignore comments for intentional test-only private API usage

### Changed
- Made tool workflow builder functions semi-public in `cerno_pkg/tools.py`
  - Renamed `_build_nmap_workflow` → `build_nmap_workflow`
  - Renamed `_build_netexec_workflow` → `build_netexec_workflow`
  - Renamed `_build_custom_workflow` → `build_custom_workflow`
  - These functions are part of the tool registry pattern and accessed via tool_definitions.py

### Documentation
- Added explicit `__all__` list to `cerno_pkg/__init__.py` documenting public API (140 exports)
- Improved code quality with proper unused variable naming (`_var` convention)
- Updated Version Increment SOP in CLAUDE.md to check `pyproject.toml` instead of git tags
  - Git tags are only created on release (main branch merge), not on every version bump
  - Always check `pyproject.toml` for current version

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

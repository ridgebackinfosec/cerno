#!/usr/bin/env python3
"""
Extract changelog section for a specific version from CHANGELOG.md.

This script parses CHANGELOG.md (Keep a Changelog format) and extracts
the content for a specified version, writing it to release_notes.md.

Usage:
    python extract_changelog.py <version>

Example:
    python extract_changelog.py 1.0.1
    # Creates release_notes.md with content from [1.0.1] section
"""

import re
import sys
from pathlib import Path


def extract_changelog_section(changelog_path: Path, version: str) -> str:
    """
    Extract changelog content for a specific version.

    Args:
        changelog_path: Path to CHANGELOG.md file
        version: Version string to extract (e.g., "1.0.1")

    Returns:
        Extracted changelog content for the version

    Raises:
        FileNotFoundError: If CHANGELOG.md doesn't exist
        ValueError: If version section not found
    """
    if not changelog_path.exists():
        raise FileNotFoundError(f"CHANGELOG.md not found at {changelog_path}")

    content = changelog_path.read_text(encoding="utf-8")

    # Pattern matches: ## [version] - YYYY-MM-DD
    # Example: ## [1.0.1] - 2026-01-09
    version_pattern = rf"## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}"

    # Find the start of this version's section
    version_match = re.search(version_pattern, content)
    if not version_match:
        raise ValueError(
            f"Version [{version}] not found in CHANGELOG.md. "
            f"Expected format: ## [{version}] - YYYY-MM-DD"
        )

    start_pos = version_match.end()

    # Find the next version header (or end of file)
    # Pattern matches any version header: ## [X.Y.Z]
    next_version_pattern = r"\n## \[\d+\.\d+\.\d+\]"
    next_match = re.search(next_version_pattern, content[start_pos:])

    if next_match:
        # Extract content between this version and next version
        end_pos = start_pos + next_match.start()
        section_content = content[start_pos:end_pos]
    else:
        # This is the last version, extract to end of file
        section_content = content[start_pos:]

    # Clean up the extracted content
    section_content = section_content.strip()

    # Remove leading/trailing blank lines
    lines = section_content.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)


def main():
    """Main entry point for changelog extraction."""
    if len(sys.argv) != 2:
        print("Usage: python extract_changelog.py <version>", file=sys.stderr)
        print("Example: python extract_changelog.py 1.0.1", file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1]
    changelog_path = Path("CHANGELOG.md")
    output_path = Path("release_notes.md")

    try:
        # Extract changelog section
        notes = extract_changelog_section(changelog_path, version)

        # Add version header to release notes
        release_notes = f"# Release v{version}\n\n{notes}\n"

        # Write to output file
        output_path.write_text(release_notes, encoding="utf-8")

        print(f"Successfully extracted changelog for version {version}")
        print(f"Release notes written to {output_path}")

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("\nAvailable versions in CHANGELOG.md:", file=sys.stderr)

        # Show available versions to help user
        if changelog_path.exists():
            content = changelog_path.read_text(encoding="utf-8")
            versions = re.findall(r"## \[(\d+\.\d+\.\d+)\]", content)
            for v in versions:
                print(f"  - {v}", file=sys.stderr)

        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

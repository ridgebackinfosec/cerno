"""Enums for CLI type-safe choices."""

from enum import Enum


class DisplayFormat(str, Enum):
    """Display format options for output."""
    SEPARATED = "separated"
    COMBINED = "combined"


class ViewFormat(str, Enum):
    """View format for files."""
    RAW = "raw"
    GROUPED = "grouped"
    HOSTS_ONLY = "hosts"


class SortMode(str, Enum):
    """Sort mode for file lists."""
    SEVERITY = "severity"
    PLUGIN_ID = "plugin_id"
    NAME = "name"
    HOSTS = "hosts"

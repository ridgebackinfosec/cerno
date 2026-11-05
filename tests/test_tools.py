"""Tests for pure command builders in cerno_pkg.tools, and the nuclei
scan-name derivation that pairs with them."""

from pathlib import Path

import pytest

from cerno_pkg.config import CernoConfig
from cerno_pkg.tools import NUCLEI_OUTPUT_NAMES, build_nuclei_cmd


@pytest.mark.unit
class TestBuildNucleiCmd:
    URLS = Path("/home/u/.cerno/scans/eng/http_urls.txt")
    OUT = Path("/home/u/.cerno/scans/eng")

    def _cmd(self, **overrides) -> str:
        cfg = CernoConfig(**overrides)
        return build_nuclei_cmd(self.URLS, self.OUT, config=cfg)

    def test_targets_the_url_list(self) -> None:
        assert f"-l {self.URLS}" in self._cmd()

    def test_all_three_outputs_land_in_the_scan_directory(self) -> None:
        """The importer reads -je from here, so the path must be predictable."""
        cmd = self._cmd()
        assert f"-je {self.OUT / NUCLEI_OUTPUT_NAMES['json']}" in cmd
        assert f"-o {self.OUT / NUCLEI_OUTPUT_NAMES['text']}" in cmd
        assert f"-me {self.OUT / NUCLEI_OUTPUT_NAMES['markdown']}" in cmd

    def test_honors_configured_templates_path_and_profile(self) -> None:
        cmd = self._cmd(
            nuclei_templates_path="/opt/nt",
            nuclei_profile="/opt/nt/profiles/pentest.yml",
        )
        assert "-ud /opt/nt" in cmd
        assert "-profile /opt/nt/profiles/pentest.yml" in cmd

    def test_profile_flag_omitted_when_unset(self) -> None:
        assert "-profile" not in self._cmd(nuclei_profile=None)
        assert "-profile" not in self._cmd(nuclei_profile="")

    def test_honors_configured_concurrency(self) -> None:
        assert "-c 4" in self._cmd(nuclei_concurrency=4)

    def test_honors_configured_user_agent(self) -> None:
        cmd = self._cmd(nuclei_user_agent="curl/8.0")
        assert "-H 'User-Agent: curl/8.0'" in cmd

    def test_default_user_agent_is_a_well_formed_mozilla_token(self) -> None:
        # A malformed UA (e.g. "Mozilla/50") is itself a fingerprint.
        assert "Mozilla/5.0 (" in self._cmd()

    def test_disables_the_update_check(self) -> None:
        assert "-duc" in self._cmd()

    def test_carries_response_size_limits_and_stats(self) -> None:
        cmd = self._cmd()
        assert "-rsr 10485760" in cmd
        assert "-rss 1048576" in cmd
        assert "-ts" in cmd
        assert "-stats" in cmd

    def test_expands_a_tilde_in_configured_paths(self) -> None:
        cmd = self._cmd(nuclei_templates_path="~/nuclei-templates")
        assert "~" not in cmd.split("-ud ")[1].split()[0]

    def test_starts_with_the_binary(self) -> None:
        assert self._cmd().startswith("nuclei ")


@pytest.mark.unit
class TestNucleiScanNameDerivation:
    """The suggested nuclei command always writes `<scan>/nuclei.json`.

    Naming every such import after the file stem means naming them all
    "nuclei", so the second import collides with the first. A file sitting
    directly inside a scan directory is named after that directory instead.
    """

    @staticmethod
    def _derive(path: Path, scans_root: Path, monkeypatch) -> str:
        import cerno
        import cerno_pkg.constants

        monkeypatch.setattr(cerno_pkg.constants, "SCANS_ROOT", scans_root)
        return cerno._derive_nuclei_scan_name(path)  # type: ignore[attr-defined]

    def test_file_in_a_scan_directory_is_named_after_it(self, tmp_path, monkeypatch):
        scans_root = tmp_path / "scans"
        results = scans_root / "GOAD" / "nuclei.json"
        results.parent.mkdir(parents=True)
        results.touch()
        assert self._derive(results, scans_root, monkeypatch) == "GOAD-nuclei"

    def test_scan_directory_name_is_sanitized(self, tmp_path, monkeypatch):
        scans_root = tmp_path / "scans"
        results = scans_root / "Client A Q1" / "nuclei.json"
        results.parent.mkdir(parents=True)
        results.touch()
        derived = self._derive(results, scans_root, monkeypatch)
        assert " " not in derived
        assert derived.endswith("-nuclei")

    def test_file_outside_the_scan_tree_keeps_its_stem(self, tmp_path, monkeypatch):
        scans_root = tmp_path / "scans"
        scans_root.mkdir()
        results = tmp_path / "engagement-web.json"
        results.touch()
        assert self._derive(results, scans_root, monkeypatch) == "engagement-web"

    def test_a_home_level_nuclei_json_does_not_borrow_the_home_dir_name(
        self, tmp_path, monkeypatch
    ):
        """Only a *scan* directory may lend its name, never any parent."""
        scans_root = tmp_path / "scans"
        scans_root.mkdir()
        results = tmp_path / "nuclei.json"
        results.touch()
        assert self._derive(results, scans_root, monkeypatch) == "nuclei"

    def test_nested_deeper_than_a_scan_directory_keeps_its_stem(
        self, tmp_path, monkeypatch
    ):
        scans_root = tmp_path / "scans"
        results = scans_root / "GOAD" / "sub" / "nuclei.json"
        results.parent.mkdir(parents=True)
        results.touch()
        assert self._derive(results, scans_root, monkeypatch) == "nuclei"

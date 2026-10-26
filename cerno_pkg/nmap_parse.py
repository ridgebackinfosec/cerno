"""Pure nmap XML parser (no database dependency).

Parses nmap ``-oX``/``-oA`` XML output into structured dataclasses: hosts that
came up, their open ports, and NSE script results (classifying vuln-script
verdicts). This mirrors the memory-efficient ``ET.iterparse`` + ``elem.clear()``
streaming idiom used by :mod:`cerno_pkg.nessus_import`.

Parsing is deliberately forgiving: a missing file, malformed XML, or a run where
no hosts came up yields an empty :class:`ParsedNmap` rather than raising, so the
ingestion path never errors on partial/failed/empty runs (mirrors the nmap
artifact-registration fix).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from .logging_setup import log_debug, log_error

# NSE verdict labels (match nse_verdicts lookup table seeds)
VERDICT_VULNERABLE = "VULNERABLE"
VERDICT_NOT_VULNERABLE = "NOT_VULNERABLE"
VERDICT_LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
VERDICT_UNKNOWN = "UNKNOWN"


@dataclass
class ParsedNmapScript:
    """One NSE script result. ``port`` is None for a host script."""

    host: str
    port: Optional[int]
    protocol: Optional[str]
    script_id: str
    raw_output: str
    verdict: str  # one of the VERDICT_* constants


@dataclass
class ParsedNmapPort:
    """One port entry for a host."""

    host: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None


@dataclass
class ParsedNmapHost:
    """One host that appeared in the scan."""

    address: str
    hostnames: list[str] = field(default_factory=list)
    state: str = "up"


@dataclass
class ParsedNmap:
    """Full parsed result of an nmap XML file."""

    hosts: list[ParsedNmapHost] = field(default_factory=list)
    ports: list[ParsedNmapPort] = field(default_factory=list)
    scripts: list[ParsedNmapScript] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.hosts and not self.ports and not self.scripts


def classify_nse_verdict(output: Optional[str]) -> str:
    """Classify an NSE script's output text into a verdict label.

    Conservative: only the explicit ``State: ...`` wording produced by nmap's
    ``vulns`` library is recognised; everything else is ``UNKNOWN``. The raw
    output is always stored alongside so a mis-classification is recoverable
    without re-running the scan.
    """
    if not output:
        return VERDICT_UNKNOWN
    text = output.upper()
    if "NOT VULNERABLE" in text:
        return VERDICT_NOT_VULNERABLE
    if "LIKELY VULNERABLE" in text:
        return VERDICT_LIKELY_VULNERABLE
    if "VULNERABLE" in text:
        return VERDICT_VULNERABLE
    return VERDICT_UNKNOWN


def _primary_address(host_elem: ET.Element) -> Optional[str]:
    """Return the host's IP address (prefer ipv4/ipv6 over mac)."""
    fallback: Optional[str] = None
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        value = addr.get("addr")
        if not value:
            continue
        if addr_type in ("ipv4", "ipv6"):
            return value
        fallback = fallback or value
    return fallback


def _iter_scripts(
    host: str, port: Optional[int], protocol: Optional[str], container: ET.Element
) -> list[ParsedNmapScript]:
    results: list[ParsedNmapScript] = []
    for script in container.findall("script"):
        script_id = script.get("id")
        if not script_id:
            continue
        output = script.get("output", "") or ""
        results.append(
            ParsedNmapScript(
                host=host,
                port=port,
                protocol=protocol,
                script_id=script_id,
                raw_output=output,
                verdict=classify_nse_verdict(output),
            )
        )
    return results


def _parse_host(host_elem: ET.Element, result: ParsedNmap) -> None:
    status = host_elem.find("status")
    state = status.get("state", "up") if status is not None else "up"

    address = _primary_address(host_elem)
    if not address:
        return

    hostnames = [
        hn.get("name", "")
        for hn in host_elem.findall("hostnames/hostname")
        if hn.get("name")
    ]
    result.hosts.append(
        ParsedNmapHost(address=address, hostnames=hostnames, state=state)
    )

    if state != "up":
        return

    # Port scripts + open ports
    for port_elem in host_elem.findall("ports/port"):
        portid = port_elem.get("portid")
        protocol = port_elem.get("protocol", "tcp")
        if not portid:
            continue
        try:
            port_num = int(portid)
        except ValueError:
            continue
        state_elem = port_elem.find("state")
        port_state = state_elem.get("state", "") if state_elem is not None else ""
        service_elem = port_elem.find("service")
        service_name = service_elem.get("name") if service_elem is not None else None

        result.ports.append(
            ParsedNmapPort(
                host=address,
                port=port_num,
                protocol=protocol,
                state=port_state,
                service_name=service_name,
            )
        )
        result.scripts.extend(_iter_scripts(address, port_num, protocol, port_elem))

    # Host scripts (port=None)
    hostscript = host_elem.find("hostscript")
    if hostscript is not None:
        result.scripts.extend(_iter_scripts(address, None, None, hostscript))


def parse_nmap_xml(xml_path: Union[str, Path]) -> ParsedNmap:
    """Parse an nmap XML file into a :class:`ParsedNmap`.

    Never raises on a missing/malformed/empty file; returns an empty result and
    logs the reason instead.
    """
    result = ParsedNmap()
    path = Path(xml_path)
    if not path.exists():
        log_debug(f"nmap XML not found, nothing to parse: {path}")
        return result

    try:
        for _event, elem in ET.iterparse(str(path), events=("end",)):
            if elem.tag == "host":
                _parse_host(elem, result)
                elem.clear()
    except ET.ParseError as exc:
        log_error(f"Failed to parse nmap XML {path}: {exc}")
        return ParsedNmap()
    except (OSError, ValueError) as exc:
        log_error(f"Error reading nmap XML {path}: {exc}")
        return ParsedNmap()

    return result

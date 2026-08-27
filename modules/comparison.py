"""Deterministic comparison of compatible NetScope JSON reports."""
from __future__ import annotations

from typing import Any, Dict, Iterable

from .exporter import FINDING_RULES_VERSION, ReportError, load_report


def _successful(report: dict) -> bool:
    return (report.get("meta") or {}).get("status", "completed") == "completed"


def _hosts(report: dict) -> set[str]:
    return {str(host.get("ip")) for host in report.get("hosts", []) if isinstance(host, dict) and host.get("alive") and host.get("ip")}


def _open_ports(report: dict) -> set[tuple[str, int]]:
    result = set()
    for host, ports in (report.get("port_results") or {}).items():
        for port in ports or []:
            if not isinstance(port, dict) or not port.get("open"):
                continue
            try:
                number = int(port.get("port"))
            except (TypeError, ValueError):
                continue
            result.add((str(host), number))
    return result


def _services(report: dict) -> dict[tuple[str, int], tuple]:
    result = {}
    for host, services in (report.get("service_guesses") or {}).items():
        for service in services or []:
            if not isinstance(service, dict):
                continue
            try:
                number = int(service.get("port"))
            except (TypeError, ValueError):
                continue
            result[(str(host), number)] = (service.get("product"), service.get("version"), service.get("extra"))
    return result


def _tls(report: dict) -> dict[tuple[str, int], Any]:
    result = {}
    for key, value in (report.get("tls_results") or {}).items():
        host, _, port = str(key).rpartition(":")
        if port.isdigit() and isinstance(value, dict):
            result[(host, int(port))] = (value or {}).get("sha256_fingerprint")
    return result


def _findings(report: dict) -> set[tuple]:
    return {(finding.get("rule_id"), finding.get("host"), finding.get("port")) for finding in report.get("findings", [])}


def compare_reports(previous: dict, current: dict) -> Dict[str, Any]:
    """Compare two report dictionaries without inferring absence from partial scans."""
    if not isinstance(previous, dict) or not isinstance(current, dict):
        raise ReportError("reports must be JSON objects")
    if (previous.get("meta") or {}).get("target") != (current.get("meta") or {}).get("target"):
        raise ReportError("reports target different targets and cannot be compared")
    if not _successful(previous) or not _successful(current):
        return {"compatible": False, "reason": "only completed reports can prove changes", "added_hosts": [], "removed_hosts": [], "opened_ports": [], "closed_ports": [], "changed_services": [], "changed_tls": [], "added_findings": [], "resolved_findings": []}
    old_coverage = previous.get("coverage") or {}
    new_coverage = current.get("coverage") or {}
    if old_coverage.get("discovery_complete") is False or new_coverage.get("discovery_complete") is False:
        return {"compatible": False, "reason": "discovery coverage is incomplete", "added_hosts": [], "removed_hosts": [], "opened_ports": [], "closed_ports": [], "changed_services": [], "changed_tls": [], "added_findings": [], "resolved_findings": []}
    old_requested = set(old_coverage.get("requested_ports") or [])
    new_requested = set(new_coverage.get("requested_ports") or [])
    if old_requested and new_requested and not old_requested <= new_requested:
        return {"compatible": False, "reason": "later report scanned a narrower port set", "added_hosts": [], "removed_hosts": [], "opened_ports": [], "closed_ports": [], "changed_services": [], "changed_tls": [], "added_findings": [], "resolved_findings": []}
    old_hosts, new_hosts = _hosts(previous), _hosts(current)
    old_ports, new_ports = _open_ports(previous), _open_ports(current)
    old_services, new_services = _services(previous), _services(current)
    old_tls, new_tls = _tls(previous), _tls(current)
    result: Dict[str, Any] = {
        "compatible": True,
        "reason": "",
        "added_hosts": sorted(new_hosts - old_hosts),
        "removed_hosts": sorted(old_hosts - new_hosts),
        "opened_ports": sorted([list(item) for item in new_ports - old_ports]),
        "closed_ports": sorted([list(item) for item in old_ports - new_ports]),
        "changed_services": [{"host": host, "port": port, "before": old_services[(host, port)], "after": new_services[(host, port)]} for host, port in sorted(old_services.keys() & new_services.keys()) if old_services[(host, port)] != new_services[(host, port)]],
        "changed_tls": [{"host": host, "port": port, "before": old_tls[(host, port)], "after": new_tls[(host, port)]} for host, port in sorted(old_tls.keys() & new_tls.keys()) if old_tls[(host, port)] != new_tls[(host, port)]],
        "added_findings": [],
        "resolved_findings": [],
    }
    old_rules = (previous.get("meta") or {}).get("finding_rules_version", FINDING_RULES_VERSION)
    new_rules = (current.get("meta") or {}).get("finding_rules_version", FINDING_RULES_VERSION)
    if old_rules == new_rules:
        result["added_findings"] = sorted([list(item) for item in _findings(current) - _findings(previous)])
        result["resolved_findings"] = sorted([list(item) for item in _findings(previous) - _findings(current)])
    else:
        result["reason"] = "finding rules changed; finding deltas omitted"
    return result


def compare_report_files(previous_path: str, current_path: str) -> Dict[str, Any]:
    return compare_reports(load_report(previous_path), load_report(current_path))

"""Reusable scan engine shared by the CLI and NiceGUI interfaces."""
from __future__ import annotations

import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .exporter import build_report, findings_for_report, write_outputs
from .ping_sweep import Host, PrivilegeUnavailable, ping_sweep, reverse_dns
from .port_scanner import PortResult, port_scan
from .service_detect import OSGuess, ServiceGuess, detect_os, detect_services
from .subdomain_enum import SubdomainHit, enumerate_subdomains
from .utils import (
    ValidationError,
    classify_target,
    is_domain,
    normalize_domain,
    parse_targets,
    parse_ports,
    validate_output_dir,
    validate_rate_limit,
    validate_timeout,
    validate_wordlist,
    validate_workers,
)


@dataclass(frozen=True)
class ScanEvent:
    type: str
    timestamp: str
    phase: str = ""
    message: str = ""
    progress: float = 0.0
    host: Optional[str] = None
    port: Optional[int] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type, "timestamp": self.timestamp, "phase": self.phase,
            "message": self.message, "progress": self.progress,
            "host": self.host, "port": self.port, "data": self.data,
        }


class CancellationToken:
    """Thread-safe cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self.is_cancelled()

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._event.wait(timeout)


@dataclass
class ScanRequest:
    target: str
    profile: str = "standard"
    discovery_method: str = "auto"
    ports: str | Sequence[int] = "top1000"
    timeout: float = 1.5
    workers: int = 200
    reverse_dns: bool = True
    banner_inspection: bool = True
    subdomain_enumeration: bool = False
    output_formats: str | Sequence[str] = "both"
    output_directory: Optional[str] = None
    rate_limit: Optional[float] = None
    wordlist: Optional[str] = None
    subdomain_method: str = "both"
    operation: str = "scan"  # ping | port | scan | all | subdomains


@dataclass
class ScanResult:
    request: ScanRequest
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: str = "running"
    started_at: str = ""
    finished_at: str = ""
    hosts: List[Host] = field(default_factory=list)
    port_results: Dict[str, List[PortResult]] = field(default_factory=dict)
    service_guesses: Dict[str, List[ServiceGuess]] = field(default_factory=dict)
    os_guesses: Dict[str, OSGuess] = field(default_factory=dict)
    subdomains: List[SubdomainHit] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    report: Optional[dict] = None


PROFILE_PORTS = {"quick": "top100", "standard": "top1000", "full": "all"}
EVENT_TYPES = {"scan_started", "phase_started", "progress_updated", "host_discovered", "port_opened", "finding_created", "scan_finished", "scan_cancelled", "scan_failed"}


class ScanEngine:
    def __init__(self, *, logger=None, resolver: Optional[Callable[[str], Iterable]] = None) -> None:
        self.logger = logger
        self.resolver = resolver or self._resolve_with_socket

    def validate_request(self, request: ScanRequest) -> ScanRequest:
        if not isinstance(request, ScanRequest):
            raise ValidationError("scan request is invalid")
        request.target = str(request.target or "").strip()
        if not request.target:
            raise ValidationError("target is required")
        if request.operation not in {"ping", "port", "scan", "all", "subdomains"}:
            raise ValidationError("unknown scan operation")
        if request.profile not in {"quick", "standard", "full", "custom"}:
            raise ValidationError("profile must be Quick, Standard, Full, or Custom")
        if request.operation == "subdomains" or request.subdomain_enumeration:
            request.target = normalize_domain(request.target)
        else:
            classify_target(request.target)
        request.timeout = validate_timeout(request.timeout)
        request.workers = validate_workers(request.workers)
        request.rate_limit = validate_rate_limit(request.rate_limit)
        request.wordlist = validate_wordlist(request.wordlist)
        # Validation is side-effect free; report writers create the directory
        # only after scanning succeeds (or a partial result is finalized).
        request.output_directory = validate_output_dir(request.output_directory, create=False)
        if request.discovery_method not in {"auto", "arp", "icmp", "dns", "manual"}:
            raise ValidationError("discovery method must be auto, arp, or icmp")
        if request.subdomain_method not in {"passive", "active", "both"}:
            raise ValidationError("subdomain method must be passive, active, or both")
        # Named profiles are authoritative.  A caller that wants an explicit
        # port expression selects ``custom`` (the CLI defaults to that mode so
        # ``--ports`` can never be silently replaced).
        if request.profile != "custom":
            request.ports = PROFILE_PORTS[request.profile]
        request.ports = parse_ports(request.ports)
        if isinstance(request.output_formats, str):
            formats = {"json", "text", "both", "html", "all"}
            if request.output_formats not in formats:
                raise ValidationError("output format must be json, text, both, html, or all")
        else:
            formats = set(request.output_formats)
            if not formats or not formats <= {"json", "text", "html"}:
                raise ValidationError("output formats must contain json, text, and/or html")
        if request.operation == "port":
            if is_domain(request.target):
                normalize_domain(request.target)
            else:
                if len(parse_targets(request.target)) != 1:
                    raise ValidationError("port operation requires one IPv4 address")
        return request

    def run(self, request: ScanRequest, *, event_sink: Optional[Callable[[ScanEvent], None]] = None, cancellation: Optional[CancellationToken] = None) -> ScanResult:
        cancellation = cancellation or CancellationToken()
        try:
            self.validate_request(request)
        except Exception as exc:
            result = ScanResult(request=request, status="failed", started_at=_now())
            result.errors.append(str(exc))
            result.finished_at = _now()
            self._emit(event_sink, "scan_failed", "validation", str(exc), 0.0, data={"error": str(exc)})
            return result
        result = ScanResult(request=request, started_at=_now())
        self._emit(event_sink, "scan_started", "", f"Scan started for {request.target}", 0.0, data={"scan_id": result.scan_id})
        try:
            if request.operation == "subdomains":
                self._run_subdomains(result, event_sink, cancellation)
            else:
                self._run_network(result, event_sink, cancellation)
                if (request.subdomain_enumeration or request.operation == "all") and is_domain(request.target):
                    self._run_subdomains(result, event_sink, cancellation)
            if cancellation.is_cancelled():
                result.status = "cancelled"
            elif result.status == "running":
                result.status = "completed"
        except PrivilegeUnavailable as exc:
            result.status = "failed"
            result.errors.append(str(exc))
            self._emit(event_sink, "scan_failed", "discovery", str(exc), 0.0, data={"error": str(exc), "privilege_unavailable": True})
        except Exception as exc:
            result.status = "failed"
            result.errors.append(str(exc))
            self._emit(event_sink, "scan_failed", "", str(exc), 0.0, data={"error": str(exc)})
        result.finished_at = _now()
        result.report = self._make_report(result)
        for finding in (result.report.get("findings") if result.report else []) or []:
            self._emit(event_sink, "finding_created", "findings", str(finding.get("title", "Finding")), 0.98, host=finding.get("host"), port=finding.get("port"), data=finding)
        if request.output_directory and result.report is not None:
            try:
                formats = request.output_formats
                write_outputs(result.report, request.output_directory, formats)
            except Exception as exc:
                result.errors.append(f"report write failed: {exc}")
                result.status = "failed"
                # Keep the in-memory result truthful even when persistence
                # fails (for example, a read-only output directory).
                result.report = self._make_report(result)
        if result.status == "cancelled":
            self._emit(event_sink, "scan_cancelled", "", "Scan cancelled; partial results preserved", 1.0, data={"partial": True})
        elif result.status == "failed":
            self._emit(event_sink, "scan_failed", "", "; ".join(result.errors) or "Scan failed", 1.0, data={"errors": result.errors})
        else:
            self._emit(event_sink, "scan_finished", "", "Scan finished", 1.0, data={"status": result.status})
        return result

    def _run_network(self, result: ScanResult, event_sink, cancellation: CancellationToken) -> None:
        request = result.request
        target_kind = classify_target(request.target)
        self._emit(event_sink, "phase_started", "discovery", "Discovering hosts", 0.02)
        if target_kind == "domain":
            addresses = self._resolve_ipv4(normalize_domain(request.target))
            result.hosts = [Host(ip=ip, alive=True, method="dns", reason="resolved A record") for ip in addresses]
            for host in result.hosts:
                self._emit(event_sink, "host_discovered", "discovery", f"Resolved {host.ip}", 0.1, host=host.ip, data=host.to_dict())
        else:
            def host_event(host: Host) -> None:
                if host.alive:
                    self._emit(event_sink, "host_discovered", "discovery", f"Host discovered: {host.ip}", 0.1, host=host.ip, data=host.to_dict())
            result.hosts = ping_sweep(request.target, timeout=request.timeout, workers=request.workers, method=request.discovery_method if request.discovery_method in {"auto", "arp", "icmp"} else "auto", logger=self.logger, on_result=host_event, cancellation=cancellation)
        if request.reverse_dns and result.hosts and not cancellation.is_cancelled():
            reverse_dns(result.hosts, timeout=request.timeout, workers=min(request.workers, 64))
        if request.operation == "ping" or cancellation.is_cancelled():
            return
        alive = [host for host in result.hosts if host.alive]
        if not alive:
            result.warnings.append("no alive hosts were discovered")
            return
        total = max(1, len(alive) * len(request.ports))
        completed = 0
        self._emit(event_sink, "phase_started", "ports", f"Scanning {len(alive)} host(s)", 0.2, data={"total": total})
        for host in alive:
            if cancellation.is_cancelled():
                break
            def port_event(port: PortResult, current_host=host.ip) -> None:
                nonlocal completed
                completed += 1
                progress = min(0.95, 0.2 + 0.7 * completed / total)
                self._emit(event_sink, "progress_updated", "ports", f"Checked {current_host}:{port.port}", progress, host=current_host, port=port.port, data=port.to_dict())
                if port.open:
                    self._emit(event_sink, "port_opened", "ports", f"Open port {current_host}:{port.port}", progress, host=current_host, port=port.port, data=port.to_dict())
            probes = port_scan(host.ip, request.ports, timeout=request.timeout, workers=request.workers, grab_banner=request.banner_inspection, logger=self.logger, on_result=port_event, cancellation=cancellation, rate_limit=request.rate_limit)
            result.port_results[host.ip] = probes
            result.service_guesses[host.ip] = detect_services(probes, ttl_observed=host.ttl)
            result.os_guesses[host.ip] = detect_os(probes, ttl_observed=host.ttl)

    def _run_subdomains(self, result: ScanResult, event_sink, cancellation: CancellationToken) -> None:
        self._emit(event_sink, "phase_started", "subdomains", "Enumerating subdomains", 0.92)
        result.subdomains = enumerate_subdomains(result.request.target, method=result.request.subdomain_method, wordlist=result.request.wordlist, workers=min(result.request.workers, 64), timeout=result.request.timeout, logger=self.logger, cancellation=cancellation)
        for hit in result.subdomains:
            self._emit(event_sink, "progress_updated", "subdomains", f"Found {hit.subdomain}", 0.95, data=hit.to_dict())

    def _make_report(self, result: ScanResult) -> dict:
        http_results = {}
        tls_results = {}
        for host, probes in result.port_results.items():
            for probe in probes:
                key = f"{host}:{probe.port}"
                if probe.http_info:
                    http_results[key] = probe.http_info
                if probe.tls_info:
                    tls_results[key] = probe.tls_info
        findings = findings_for_report(result.hosts, result.port_results, tls_results)
        return build_report(target=result.request.target, hosts=result.hosts, port_results=result.port_results, service_guesses=result.service_guesses, os_guesses=result.os_guesses, subdomains=result.subdomains, started_at=result.started_at, finished_at=result.finished_at or _now(), scan_meta={"profile": result.request.profile, "discovery_method": result.request.discovery_method, "ports": result.request.ports, "timeout": result.request.timeout, "workers": result.request.workers, "rdns": result.request.reverse_dns, "banner": result.request.banner_inspection, "rate_limit": result.request.rate_limit}, http_results=http_results, tls_results=tls_results, findings=findings, warnings=result.warnings, errors=result.errors, status=result.status, scan_id=result.scan_id, coverage={"discovery_complete": result.status != "cancelled", "requested_ports": list(result.request.ports), "completed_ports_by_host": {host: len(probes) for host, probes in result.port_results.items()}, "subdomain_complete": result.status == "completed"})

    def _emit(self, sink, event_type: str, phase: str, message: str, progress: float, *, host=None, port=None, data=None) -> None:
        if sink is not None:
            sink(ScanEvent(type=event_type, timestamp=_now(), phase=phase, message=message, progress=max(0.0, min(1.0, progress)), host=host, port=port, data=data or {}))

    @staticmethod
    def _resolve_with_socket(domain: str):
        return socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)

    def _resolve_ipv4(self, domain: str) -> list[str]:
        addresses = []
        try:
            infos = self.resolver(domain)
        except (OSError, socket.gaierror) as exc:
            raise ValidationError(f"could not resolve domain {domain}: {exc}") from exc
        for info in infos:
            sockaddr = info[4] if isinstance(info, tuple) and len(info) > 4 else info
            candidate = sockaddr[0] if isinstance(sockaddr, tuple) else sockaddr
            try:
                if "." in str(candidate):
                    addresses.append(str(candidate))
            except Exception:
                continue
        return sorted(set(addresses), key=lambda item: tuple(int(part) for part in item.split(".")))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_scan(request: ScanRequest, *, event_sink=None, cancellation: CancellationToken | None = None, logger=None) -> ScanResult:
    """Convenience wrapper for callers that do not need an engine instance."""
    return ScanEngine(logger=logger).run(request, event_sink=event_sink, cancellation=cancellation)


def create_report(result: ScanResult) -> dict:
    """Return the canonical report for an already completed/partial result."""
    return ScanEngine()._make_report(result)  # noqa: SLF001 - deliberate public facade

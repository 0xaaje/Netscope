"""Pure form validation and live-scan state used by the NiceGUI layer."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .engine import ScanEvent, ScanRequest
from .utils import ValidationError, classify_target, normalize_domain, parse_ports, validate_rate_limit, validate_timeout, validate_workers


@dataclass
class ScanForm:
    target: str = ""
    profile: str = "standard"
    discovery_method: str = "auto"
    ports: str = "top1000"
    timeout: Any = 1.5
    workers: Any = 200
    reverse_dns: bool = True
    banner_inspection: bool = True
    subdomain_enumeration: bool = False
    output_formats: List[str] = field(default_factory=lambda: ["json", "text", "html"])
    output_directory: str = "output"
    rate_limit: Any = None
    authorization_confirmed: bool = False

    def to_request(self) -> ScanRequest:
        return ScanRequest(
            target=self.target, profile=self.profile, discovery_method=self.discovery_method,
            ports=self.ports, timeout=float(self.timeout), workers=int(self.workers),
            reverse_dns=self.reverse_dns, banner_inspection=self.banner_inspection,
            subdomain_enumeration=self.subdomain_enumeration,
            output_formats=self.output_formats, output_directory=self.output_directory,
            rate_limit=self.rate_limit,
        )


def validate_scan_form(form: ScanForm) -> Dict[str, str]:
    errors: Dict[str, str] = {}
    target = (form.target or "").strip()
    if not target:
        errors["target"] = "Target is required."
    else:
        try:
            kind = classify_target(target)
            if form.subdomain_enumeration and kind != "domain":
                errors["subdomain_enumeration"] = "Subdomain enumeration requires a domain target."
            if form.discovery_method == "dns" and kind != "domain":
                errors["discovery_method"] = "DNS discovery requires a domain target."
        except ValidationError as exc:
            errors["target"] = str(exc)
    if form.profile not in {"quick", "standard", "full", "custom"}:
        errors["profile"] = "Choose Quick, Standard, Full, or Custom."
    try:
        validate_timeout(form.timeout)
    except ValidationError as exc:
        errors["timeout"] = str(exc)
    try:
        validate_workers(form.workers)
    except ValidationError as exc:
        errors["workers"] = str(exc)
    try:
        validate_rate_limit(form.rate_limit)
    except ValidationError as exc:
        errors["rate_limit"] = str(exc)
    try:
        if form.profile == "custom":
            parse_ports(form.ports)
    except ValidationError as exc:
        errors["ports"] = str(exc)
    if not form.output_formats:
        errors["output_formats"] = "Select at least one report format."
    elif not set(form.output_formats) <= {"json", "text", "html"}:
        errors["output_formats"] = "Choose JSON, text, and/or HTML."
    elif "json" not in form.output_formats:
        errors["output_formats"] = "JSON is required so this scan appears in Reports and Compare."
    if not (form.output_directory or "").strip():
        errors["output_directory"] = "Output location is required."
    if not form.authorization_confirmed:
        errors["authorization_confirmed"] = "Confirm that you are authorized to scan this target."
    return errors


@dataclass
class LiveScanState:
    status: str = "idle"
    phase: str = ""
    progress: float = 0.0
    current_host: Optional[str] = None
    elapsed_seconds: float = 0.0
    hosts_discovered: int = 0
    open_ports: int = 0
    activity: List[str] = field(default_factory=list)
    error: Optional[str] = None
    started_monotonic: Optional[float] = None

    def start(self) -> None:
        self.status = "running"
        self.phase = "starting"
        self.progress = 0.0
        self.error = None
        self.activity.clear()
        self.started_monotonic = time.monotonic()

    def cancel_requested(self) -> None:
        if self.status == "running":
            self.status = "cancelling"

    def apply(self, event: ScanEvent | dict) -> None:
        data = event.to_dict() if isinstance(event, ScanEvent) else event
        event_type = data.get("type")
        self.phase = data.get("phase") or self.phase
        self.progress = max(self.progress, float(data.get("progress") or 0.0))
        if data.get("host"):
            self.current_host = data["host"]
        if event_type == "scan_started":
            self.start()
        elif event_type == "host_discovered":
            self.hosts_discovered += 1
        elif event_type == "port_opened":
            self.open_ports += 1
        elif event_type in {"phase_started", "progress_updated"}:
            pass
        elif event_type == "scan_cancelled":
            self.status = "cancelled"
        elif event_type == "scan_finished":
            self.status = "completed"
        elif event_type == "scan_failed":
            self.status = "failed"
            self.error = data.get("message") or (data.get("data") or {}).get("error") or "Scan failed"
        message = data.get("message")
        if message:
            self.activity.append(message)
            self.activity = self.activity[-200:]
        if self.started_monotonic is not None:
            self.elapsed_seconds = max(0.0, time.monotonic() - self.started_monotonic)

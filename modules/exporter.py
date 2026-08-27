"""Report creation, persistence, HTML rendering, and conservative findings."""
from __future__ import annotations

import html
import json
import os
import tempfile
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import __version__
from .ping_sweep import Host
from .port_scanner import PortResult
from .service_detect import OSGuess, ServiceGuess
from .subdomain_enum import SubdomainHit


SCHEMA_VERSION = 2
FINDING_RULES_VERSION = 1


class ReportError(ValueError):
    """Raised when a report is unreadable or incompatible."""


def _to_dict(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    return value


def build_report(
    *,
    target: str,
    hosts: List[Host],
    port_results: Dict[str, List[PortResult]],
    service_guesses: Dict[str, List[ServiceGuess]],
    os_guesses: Dict[str, OSGuess],
    subdomains: Optional[List[SubdomainHit]] = None,
    started_at: str,
    finished_at: str,
    scan_meta: Optional[Dict[str, Any]] = None,
    http_results: Optional[Dict[str, Any]] = None,
    tls_results: Optional[Dict[str, Any]] = None,
    findings: Optional[List[dict]] = None,
    warnings: Optional[List[str]] = None,
    errors: Optional[List[str]] = None,
    status: str = "completed",
    scan_id: Optional[str] = None,
    coverage: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if status not in {"completed", "cancelled", "failed"}:
        raise ReportError(f"invalid report status: {status}")
    port_map = {
        host: [_to_dict(port) for port in sorted(probes, key=lambda item: item.port)]
        for host, probes in (port_results or {}).items()
    }
    # Keep HTTP/TLS maps separately while retaining the PortResult fields for
    # callers that consume the original report shape.
    inferred_http = http_results or {}
    inferred_tls = tls_results or {}
    for host, probes in port_map.items():
        for probe in probes:
            key = f"{host}:{probe.get('port')}"
            if probe.get("http_info"):
                inferred_http[key] = probe["http_info"]
            if probe.get("tls_info"):
                inferred_tls[key] = probe["tls_info"]
    return {
        "schema_version": SCHEMA_VERSION,
        "meta": {
            "tool": "NetScope",
            "version": __version__,
            "finding_rules_version": FINDING_RULES_VERSION,
            "scan_id": scan_id or uuid.uuid4().hex,
            "status": status,
            "target": target,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_s": _duration_seconds(started_at, finished_at),
            "scan": scan_meta or {},
        },
        "hosts": [_to_dict(host) for host in hosts],
        "alive_hosts": [host.ip for host in hosts if host.alive],
        "port_results": port_map,
        "service_guesses": {
            host: [_to_dict(guess) for guess in guesses]
            for host, guesses in (service_guesses or {}).items()
        },
        "os_guesses": {
            host: _to_dict(guess) for host, guess in (os_guesses or {}).items() if guess is not None
        },
        "http_results": inferred_http,
        "tls_results": inferred_tls,
        "subdomains": [_to_dict(subdomain) for subdomain in (subdomains or [])],
        "findings": findings or [],
        "warnings": warnings or [],
        "errors": errors or [],
        "coverage": coverage or {
            "discovery_complete": True,
            "requested_ports": sorted({probe.get("port") for probes in port_map.values() for probe in probes if probe.get("port") is not None}),
            "completed_ports_by_host": {host: len(probes) for host, probes in port_map.items()},
        },
    }


def _duration_seconds(start_iso: str, end_iso: str) -> float:
    try:
        start = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        end = datetime.strptime(end_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return max(0.0, (end - start).total_seconds())
    except Exception:
        return 0.0


def _atomic_write(path: str, content: str) -> str:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return str(destination.resolve())


def write_json(report: Dict[str, Any], path: str) -> str:
    return _atomic_write(path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def write_text(report: Dict[str, Any], path: str) -> str:
    return _atomic_write(path, render_text(report))


def write_html(report: Dict[str, Any], path: str) -> str:
    return _atomic_write(path, render_html(report))


def write_outputs(report: Dict[str, Any], out_dir: str, fmt: str | Iterable[str]) -> List[str]:
    """Write exactly the requested report formats.

    The CLI uses one of the named bundles; the UI supplies a selectable list,
    so lists are accepted here as well and are written without inventing a
    fifth format name.
    """
    if isinstance(fmt, str):
        if fmt not in {"json", "text", "both", "html", "all"}:
            raise ReportError("format must be json, text, both, html, or all")
        selected = {"json", "text"} if fmt == "both" else {"json", "text", "html"} if fmt == "all" else {fmt}
    else:
        selected = {str(item).lower() for item in fmt}
        if not selected or not selected <= {"json", "text", "html"}:
            raise ReportError("formats must contain json, text, and/or html")
    output = []
    if "json" in selected:
        output.append(write_json(report, str(Path(out_dir) / "report.json")))
    if "text" in selected:
        output.append(write_text(report, str(Path(out_dir) / "report.txt")))
    if "html" in selected:
        output.append(write_html(report, str(Path(out_dir) / "report.html")))
    return output


def render_text(report: Dict[str, Any]) -> str:
    meta = report.get("meta", {})
    lines: List[str] = ["=" * 72, " NetScope - Network Scan Report", "=" * 72]
    lines.extend([
        f" Target        : {meta.get('target', '?')}",
        f" Status        : {meta.get('status', 'completed')}",
        f" Started (UTC) : {meta.get('started_at', '?')}",
        f" Finished (UTC): {meta.get('finished_at', '?')}",
        f" Duration      : {float(meta.get('duration_s', 0) or 0):.2f}s",
        "",
    ])
    scan = meta.get("scan", {})
    if scan:
        lines.extend([" Scan parameters", "-" * 72])
        lines.extend(f"   {key:<18}: {value}" for key, value in scan.items())
        lines.append("")
    hosts = report.get("hosts", []) or []
    lines.extend([f" Hosts ({len(hosts)})", "-" * 72, "   IP                 Alive  Method RTT      MAC                Hostname"])
    for host in hosts:
        rtt = f"{host['rtt_ms']:.1f}ms" if host.get("rtt_ms") is not None else "-"
        lines.append(f"   {str(host.get('ip', '?')):<18} {'yes' if host.get('alive') else 'no':<6} {(host.get('method') or '-'):<6} {rtt:<8} {(host.get('mac') or '-'):<18} {host.get('hostname') or '-'}")
    lines.append("")
    for host, ports in (report.get("port_results") or {}).items():
        lines.extend([f" Host {host} — open ports", "-" * 72])
        open_ports = [port for port in ports if port.get("open")]
        if not open_ports:
            lines.append("   (no open ports in the scanned range)")
        else:
            lines.append("   Port   State     Hint           RTT      Banner")
            for port in open_ports:
                banner = " ".join(str(port.get("banner") or "").split())[:60]
                rtt = f"{port.get('rtt_ms'):.1f}ms" if port.get("rtt_ms") is not None else "-"
                lines.append(f"   {int(port.get('port', 0)):<6} {str(port.get('state', '?')):<9} {str(port.get('service_hint') or '-'):<14} {rtt:<8} {banner}")
        services = (report.get("service_guesses") or {}).get(host) or []
        if services:
            lines.extend(["", f"   Service guesses for {host}"])
            lines.extend(f"     {service.get('product', '?'):<20} {service.get('version') or '-':<14} [{service.get('confidence', 'low')}]" for service in services)
        os_guess = (report.get("os_guesses") or {}).get(host)
        if os_guess:
            lines.extend(["", f"   OS guess: {os_guess.get('family', '?')} {os_guess.get('version') or '-'} [{os_guess.get('confidence', 'low')}] ({os_guess.get('reason', '')})"])
        lines.append("")
    findings = report.get("findings") or []
    lines.extend([f" Findings ({len(findings)})", "-" * 72])
    for finding in findings:
        lines.append(f"   [{finding.get('severity', 'info').upper()}] {finding.get('title', '?')} — {finding.get('host', '?')}:{finding.get('port') or '-'}")
        lines.append(f"      Evidence: {finding.get('evidence', '')}")
        lines.append(f"      Remediation: {finding.get('remediation', '')}")
    lines.extend(["", f" Subdomains ({len(report.get('subdomains') or [])})", "-" * 72])
    for subdomain in report.get("subdomains") or []:
        lines.append(f"   {subdomain.get('subdomain', '?'):<40} {','.join(subdomain.get('ips') or [])} [{subdomain.get('source', '?')}]")
    lines.extend(["", "=" * 72, " End of report", "=" * 72, ""])
    return "\n".join(lines)


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html(report: Dict[str, Any]) -> str:
    meta = report.get("meta", {})
    cards = "".join(f'<div class="metric"><span>{_e(label)}</span><strong>{_e(value)}</strong></div>' for label, value in (
        ("Status", meta.get("status", "completed")), ("Hosts", len(report.get("hosts") or [])),
        ("Open ports", sum(1 for ports in (report.get("port_results") or {}).values() for port in ports if port.get("open"))),
        ("Findings", len(report.get("findings") or [])),
    ))
    host_rows = []
    for host in report.get("hosts") or []:
        ip = host.get("ip", "?")
        ports = (report.get("port_results") or {}).get(ip, [])
        open_ports = [port for port in ports if port.get("open")]
        details = "".join(f'<li><code>{_e(port.get("port"))}</code> {_e(port.get("service_hint") or "unknown")} — {_e(port.get("banner") or "no banner")}</li>' for port in open_ports)
        host_rows.append(f'<tr><td><code>{_e(ip)}</code></td><td>{_e(host.get("hostname") or "-")}</td><td>{_e(host.get("os_guess") or (report.get("os_guesses") or {}).get(ip, {}).get("family", "-"))}</td><td>{len(open_ports)}</td><td><details><summary>view</summary><ul>{details or "<li>none</li>"}</ul></details></td></tr>')
    finding_rows = "".join(f'<tr><td><span class="severity {_e(finding.get("severity", "info"))}">{_e(finding.get("severity", "info"))}</span></td><td>{_e(finding.get("title"))}</td><td><code>{_e(finding.get("host"))}:{_e(finding.get("port") or "-")}</code></td><td>{_e(finding.get("evidence"))}</td><td>{_e(finding.get("remediation"))}</td></tr>' for finding in report.get("findings") or [])
    subdomains = "".join(f'<li><code>{_e(sub.get("subdomain"))}</code> — {_e(", ".join(sub.get("ips") or []))} ({_e(sub.get("source"))})</li>' for sub in report.get("subdomains") or [])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScope report — {_e(meta.get("target", ""))}</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1220; --panel:#111c2e; --line:#253553; --text:#e6edf7; --muted:#93a4be; --accent:#35b8e8; --ok:#41d392; --warn:#f2b84b; --bad:#ff6b75; }}
* {{ box-sizing:border-box; }} body {{ margin:0; padding:32px; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }} main {{ max-width:1200px; margin:auto; }} h1 {{ font-size:26px; margin:0 0 4px; }} h2 {{ font-size:18px; margin:28px 0 10px; }} .muted {{ color:var(--muted); }} .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:24px 0; }} .metric, section {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }} .metric span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }} .metric strong {{ display:block; font-size:24px; margin-top:5px; color:var(--accent); }} table {{ width:100%; border-collapse:collapse; }} th,td {{ text-align:left; vertical-align:top; padding:10px 8px; border-bottom:1px solid var(--line); }} th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; }} code {{ color:#bceeff; font:13px ui-monospace,SFMono-Regular,Consolas,monospace; }} .severity {{ border-radius:999px; padding:2px 8px; font-size:12px; }} .high {{ color:#1c1114; background:var(--bad); }} .medium {{ color:#211909; background:var(--warn); }} .low,.info {{ color:#082017; background:var(--ok); }} details summary {{ color:var(--accent); cursor:pointer; }} ul {{ margin:8px 0 0; }} @media(max-width:720px) {{ body {{ padding:16px; }} th:nth-child(2),td:nth-child(2) {{ display:none; }} }}
</style></head><body><main><h1>NetScope network scan report</h1><div class="muted">Target: <code>{_e(meta.get("target"))}</code> · Started {_e(meta.get("started_at"))} · Duration {_e(meta.get("duration_s", 0))}s</div><div class="metrics">{cards}</div>
<section><h2>Hosts and open services</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>OS guess</th><th>Open ports</th><th>Details</th></tr></thead><tbody>{''.join(host_rows) or '<tr><td colspan="5" class="muted">No hosts recorded.</td></tr>'}</tbody></table></section>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Affected</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>{finding_rows or '<tr><td colspan="5" class="muted">No findings. Open ports are observations, not proof of vulnerability.</td></tr>'}</tbody></table></section>
<section><h2>Subdomains</h2><ul>{subdomains or '<li class="muted">Enumeration not run or no results.</li>'}</ul></section>
<p class="muted">Generated by NetScope. Banner and OS results are best-effort observations unless explicitly marked confirmed.</p></main></body></html>'''


def load_report(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"could not read report {path}: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("meta"), dict):
        raise ReportError("report is not a NetScope object")
    if "schema_version" not in report:
        report["schema_version"] = 1
    if report["schema_version"] not in {1, SCHEMA_VERSION}:
        raise ReportError(f"unsupported report schema: {report['schema_version']}")
    return report


def findings_for_report(hosts: Iterable[Host], port_results: Dict[str, List[PortResult]], tls_results: Optional[Dict[str, Any]] = None) -> List[dict]:
    findings: List[dict] = []
    for host, probes in port_results.items():
        for probe in probes:
            if not probe.open:
                continue
            if probe.port == 23:
                findings.append({"rule_id": "cleartext-telnet", "severity": "medium", "title": "Unencrypted Telnet service observed", "host": host, "port": probe.port, "evidence": "TCP connect succeeded on port 23; this is an observation, not proof of exploitable access.", "remediation": "Prefer SSH or another encrypted management protocol and restrict administrative access.", "classification": "observation", "confidence": "high"})
            elif probe.port in {21, 110, 143}:
                findings.append({"rule_id": "cleartext-service", "severity": "low", "title": "Cleartext application service observed", "host": host, "port": probe.port, "evidence": f"TCP connect succeeded on port {probe.port}.", "remediation": "Confirm the service is required and use a TLS-protected alternative where possible.", "classification": "observation", "confidence": "medium"})
    for key, tls in (tls_results or {}).items():
        not_after = str((tls or {}).get("not_after") or "")
        if not_after and not_after < datetime.now(timezone.utc).isoformat():
            host, _, port = key.rpartition(":")
            findings.append({"rule_id": "tls-expired", "severity": "high", "title": "TLS certificate appears expired", "host": host, "port": int(port) if port.isdigit() else None, "evidence": f"Certificate not_after={not_after}.", "remediation": "Replace the certificate and verify renewal monitoring.", "classification": "confirmed", "confidence": "high"})
    return findings

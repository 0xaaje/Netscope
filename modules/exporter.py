"""NetScope - result aggregation and export (JSON + human-readable text)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .ping_sweep import Host
from .port_scanner import PortResult
from .service_detect import OSGuess, ServiceGuess
from .subdomain_enum import SubdomainHit


# --- Result envelope -------------------------------------------------------

def build_report(
    *,
    target: str,
    hosts: List[Host],
    port_results: Dict[str, List[PortResult]],   # host -> list
    service_guesses: Dict[str, List[ServiceGuess]],  # host -> list
    os_guesses: Dict[str, OSGuess],              # host -> guess
    subdomains: Optional[List[SubdomainHit]] = None,
    started_at: str,
    finished_at: str,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Bundle all scan results into a single JSON-serializable dict."""
    return {
        "meta": {
            "tool": "NetScope",
            "version": "1.0.0",
            "target": target,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_s": _duration_seconds(started_at, finished_at),
            "scan": scan_meta or {},
        },
        "hosts": [h.to_dict() for h in hosts],
        "alive_hosts": [h.ip for h in hosts if h.alive],
        "port_results": {
            host: [p.to_dict() for p in sorted(probes, key=lambda r: r.port)]
            for host, probes in port_results.items()
        },
        "service_guesses": {
            host: [s.to_dict() for s in guesses]
            for host, guesses in service_guesses.items()
        },
        "os_guesses": {
            host: g.to_dict()
            for host, g in os_guesses.items()
        },
        "subdomains": [s.to_dict() for s in (subdomains or [])],
    }


def _duration_seconds(start_iso: str, end_iso: str) -> float:
    try:
        s = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        e = datetime.strptime(end_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return max(0.0, (e - s).total_seconds())
    except Exception:
        return 0.0


# --- Writers ---------------------------------------------------------------

def write_json(report: Dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=False, ensure_ascii=False)
    return os.path.abspath(path)


def write_text(report: Dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_text(report))
    return os.path.abspath(path)


def render_text(report: Dict[str, Any]) -> str:
    """Render the report dict into a human-readable text report."""
    out: List[str] = []
    meta = report.get("meta", {})
    out.append("=" * 72)
    out.append(" NetScope - Network Scan Report")
    out.append("=" * 72)
    out.append(f" Target        : {meta.get('target', '?')}")
    out.append(f" Started (UTC) : {meta.get('started_at', '?')}")
    out.append(f" Finished (UTC): {meta.get('finished_at', '?')}")
    out.append(f" Duration      : {meta.get('duration_s', 0):.2f}s")
    out.append("")

    scan = meta.get("scan", {})
    if scan:
        out.append(" Scan parameters")
        out.append("-" * 72)
        for k, v in scan.items():
            out.append(f"   {k:<14s}: {v}")
        out.append("")

    # Hosts
    out.append(f" Hosts ({len(report.get('hosts', []))})")
    out.append("-" * 72)
    out.append(f"   {'IP':<17s} {'Alive':<6s} {'Method':<6s} {'RTT':<8s} {'MAC':<18s} Hostname")
    for h in report.get("hosts", []):
        rtt_str = f"{h['rtt_ms']:.1f}ms" if h.get('rtt_ms') is not None else "-"
        out.append(
            f"   {h['ip']:<17s} "
            f"{'yes' if h['alive'] else 'no':<6s} "
            f"{(h.get('method') or '-'):<6s} "
            f"{rtt_str:<8s} "
            f"{(h.get('mac') or '-'):<18s} "
            f"{h.get('hostname') or '-'}"
        )
    out.append("")

    # Per-host detail
    for host, ports in (report.get("port_results") or {}).items():
        out.append(f" Host {host}  —  open ports")
        out.append("-" * 72)
        if not ports:
            out.append("   (no open ports in the scanned range)")
        else:
            out.append(f"   {'Port':<6s} {'State':<9s} {'Hint':<14s} {'RTT':<8s} Banner")
            for p in ports:
                if not p.get("open"):
                    continue
                banner = (p.get("banner") or "").replace("\r", " ").replace("\n", " ")
                if len(banner) > 60:
                    banner = banner[:57] + "..."
                rtt_str = (
                    f"{p['rtt_ms']:.1f}ms"
                    if p.get("rtt_ms") is not None
                    else "-"
                )
                out.append(
                    f"   {p['port']:<6d} "
                    f"{p.get('state','?'):<9s} "
                    f"{(p.get('service_hint') or '-'):<14s} "
                    f"{rtt_str:<8s} "
                    f"{banner}"
                )
        out.append("")

        # Services
        svcs = (report.get("service_guesses") or {}).get(host) or []
        if svcs:
            out.append(f"   Service guesses for {host}")
            out.append("   " + "-" * 68)
            for s in svcs:
                line = f"     {s['product']:<18s} {s.get('version') or '-':<14s} "
                if s.get("extra"):
                    line += f"({s['extra']}) "
                line += f"[{s.get('confidence','low')}]"
                out.append(line)
            out.append("")

        # OS
        osg = (report.get("os_guesses") or {}).get(host)
        if osg:
            out.append(
                f"   OS guess for {host}: {osg.get('family','?')} "
                f"{(osg.get('version') or '').strip() or '-'} "
                f"[{osg.get('confidence','low')}]  ({osg.get('reason','')})"
            )
            out.append("")

    # Subdomains
    subs = report.get("subdomains") or []
    out.append(f" Subdomains ({len(subs)})")
    out.append("-" * 72)
    if not subs:
        out.append("   (none — subdomain enumeration not run, or no results)")
    else:
        for s in subs:
            ips = ",".join((s.get("ips") or [])[:3])
            if len(s.get("ips") or []) > 3:
                ips += f" (+{len(s['ips'])-3})"
            out.append(
                f"   {s['subdomain']:<40s} "
                f"{'ALIVE' if s.get('alive') else 'seen ':<6s} "
                f"{ips:<24s} [{s.get('source','?')}]"
            )
    out.append("")
    out.append("=" * 72)
    out.append(" End of report")
    out.append("=" * 72)
    return "\n".join(out)

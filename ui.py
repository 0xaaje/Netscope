"""Local NiceGUI browser interface for NetScope.

The UI is intentionally Python-only.  The blocking scan engine runs through
NiceGUI's ``run.io_bound`` pool and posts immutable events into a queue; a
page timer drains that queue on the event loop before touching components.
"""
from __future__ import annotations

import json
import queue
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from modules import __version__
from modules.comparison import compare_report_files
from modules.engine import CancellationToken, ScanEngine, ScanEvent
from modules.exporter import ReportError, load_report, render_html, render_text
from modules.settings import load_settings, save_settings
from modules.ui_state import LiveScanState, ScanForm, validate_scan_form
from modules.utils import ValidationError, validate_output_dir

try:  # Keep the CLI importable when optional UI dependencies are absent.
    from nicegui import run, ui
except ImportError:  # pragma: no cover - exercised when dependencies are absent
    run = None
    ui = None


APP_ROOT = Path(__file__).resolve().parent


def _resolve_output_directory(value: str | Path) -> Path:
    """Anchor relative UI output paths to the application directory."""
    path = Path(str(value or "")).expanduser()
    return path if path.is_absolute() else APP_ROOT / path


def _normalize_output_formats(value: Any) -> list[str]:
    """Normalize NiceGUI select values (labels, indices, or option dicts)."""
    options = ("json", "text", "html")
    if not isinstance(value, (list, tuple, set)):
        value = [value]
    normalized: list[str] = []
    for item in value:
        if isinstance(item, dict):
            item = item.get("label", item.get("value"))
        if isinstance(item, int) and 0 <= item < len(options):
            item = options[item]
        item = str(item).lower()
        if item in options and item not in normalized:
            normalized.append(item)
    return normalized


def _report_files(root: str | Path) -> tuple[list[Path], list[str]]:
    directory = Path(root).expanduser()
    if not directory.exists():
        return [], []
    valid: list[Path] = []
    errors: list[str] = []
    for path in sorted(directory.rglob("report.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            load_report(str(path))
            valid.append(path)
        except ReportError as exc:
            errors.append(f"{path}: {exc}")
    return valid, errors


def _report_rows(root: str | Path) -> tuple[list[dict], list[str]]:
    files, errors = _report_files(root)
    rows = []
    for path in files:
        try:
            report = load_report(str(path))
        except ReportError:
            continue
        meta = report.get("meta") or {}
        rows.append({
            "scan_id": meta.get("scan_id", path.parent.name),
            "target": meta.get("target", "?"),
            "status": meta.get("status", "completed"),
            "started_at": meta.get("started_at", ""),
            "hosts": len(report.get("alive_hosts") or []),
            "path": str(path),
        })
    return rows, errors


def aggregate_assets(reports: Iterable[dict]) -> list[dict]:
    """Merge the most recent host observation from saved reports."""
    latest: dict[str, tuple[str, dict, dict]] = {}
    for report in reports:
        meta = report.get("meta") or {}
        seen = str(meta.get("finished_at") or meta.get("started_at") or "")
        for host in report.get("hosts") or []:
            if not host.get("ip") or not host.get("alive"):
                continue
            ip = str(host["ip"])
            previous = latest.get(ip)
            if previous is None or seen >= previous[0]:
                latest[ip] = (seen, report, host)
    rows = []
    for ip, (seen, report, host) in sorted(latest.items()):
        ports = (report.get("port_results") or {}).get(ip) or []
        findings = [finding for finding in report.get("findings") or [] if finding.get("host") == ip]
        severity_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
        highest = max((finding.get("severity", "info") for finding in findings), key=lambda value: severity_rank.get(value, 0), default="info")
        os_guess = (report.get("os_guesses") or {}).get(ip) or {}
        rows.append({
            "ip": ip, "hostname": host.get("hostname") or "-", "mac": host.get("mac") or "-",
            "vendor": host.get("vendor") or "-", "os": os_guess.get("family", "Unknown"),
            "confidence": os_guess.get("confidence", "low"), "open_ports": sum(1 for port in ports if port.get("open")),
            "highest_risk": highest, "last_seen": seen, "report": report,
        })
    return rows


def _run_engine(request, token: CancellationToken, event_queue: queue.Queue):
    return ScanEngine().run(request, cancellation=token, event_sink=event_queue.put)


def build_app() -> None:
    if ui is None:
        raise RuntimeError("NiceGUI is not installed; run `python -m pip install -r requirements.txt`")
    settings = load_settings()
    output_root = _resolve_output_directory(str(settings.get("output_directory", "output")))
    live = LiveScanState()
    event_queue: queue.Queue = queue.Queue()
    cancellation: Optional[CancellationToken] = None
    current_result = None
    reports_error_label = None
    sections: dict[str, Any] = {}

    ui.add_css('''
      :root { --ns-bg:#0b1220; --ns-panel:#111c2e; --ns-panel2:#16243a; --ns-line:#263a5b; --ns-text:#e7eef8; --ns-muted:#91a5c1; --ns-accent:#35b8e8; --ns-ok:#42d392; --ns-warn:#f2b84b; --ns-bad:#ff6b75; }
      body { background:var(--ns-bg); color:var(--ns-text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
      .ns-card { background:var(--ns-panel); border:1px solid var(--ns-line); border-radius:12px; box-shadow:0 8px 28px rgba(0,0,0,.16); }
      .ns-muted { color:var(--ns-muted); } .ns-mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
      .ns-kicker { color:var(--ns-muted); text-transform:uppercase; letter-spacing:.1em; font-size:11px; }
      .q-field--outlined .q-field__control { border-color:var(--ns-line); } .q-field__label { color:var(--ns-muted); }
      .q-table th { color:var(--ns-muted); text-transform:uppercase; font-size:11px; letter-spacing:.06em; }
      .q-table tbody td { border-color:var(--ns-line); } .q-drawer { background:#0d1728; border-color:var(--ns-line); }
    ''')

    def switch(section: str) -> None:
        for key, container in sections.items():
            container.set_visibility(key == section)
        if section == "dashboard":
            dashboard.refresh()
        elif section == "assets":
            assets.refresh()
        elif section == "reports":
            reports.refresh()
        elif section == "compare":
            compare.refresh()

    with ui.header().classes("items-center px-6 py-3 bg-[#0d1728] border-b border-[#263a5b]"):
        ui.label("NETSCOPE").classes("text-lg font-semibold tracking-[.18em] text-[#35b8e8]")
        ui.label(f"v{__version__}").classes("ns-mono text-xs text-[#91a5c1] ml-2")
        ui.label("network operations").classes("ns-muted text-sm ml-3")
        ui.space()
        ui.label("LOCAL · IPv4 · AUTHORIZED USE ONLY").classes("ns-kicker")
    with ui.left_drawer(value=True).classes("p-3"):
        ui.label("WORKSPACE").classes("ns-kicker px-3 pt-3 pb-2")
        for label, key, icon in (("Dashboard", "dashboard", "dashboard"), ("New scan", "new", "add_circle_outline"), ("Live scan", "live", "monitor_heart"), ("Assets", "assets", "lan"), ("Reports", "reports", "description"), ("Compare", "compare", "compare_arrows"), ("Settings", "settings", "tune")):
            ui.button(label, icon=icon, on_click=lambda key=key: switch(key)).props("flat align=left no-caps").classes("w-full text-left text-[#dbe7f6] mb-1")
        ui.separator().classes("my-5")
        ui.label("Scans stay on this machine. The web server binds to loopback by default.").classes("ns-muted text-xs leading-5 px-3")

    with ui.column().classes("w-full max-w-[1500px] mx-auto p-5 md:p-8 gap-5"):
        with ui.column() as dashboard_section:
            sections["dashboard"] = dashboard_section
            @ui.refreshable
            def dashboard():
                rows, errors = _report_rows(output_root)
                all_reports = []
                for row in rows:
                    try:
                        all_reports.append(load_report(row["path"]))
                    except ReportError:
                        pass
                alive = sum(len(report.get("alive_hosts") or []) for report in all_reports)
                open_ports = sum(sum(1 for port in ports if port.get("open")) for report in all_reports for ports in (report.get("port_results") or {}).values())
                services = sum(len(services) for report in all_reports for services in (report.get("service_guesses") or {}).values())
                severity = defaultdict(int)
                for report in all_reports:
                    for finding in report.get("findings") or []:
                        severity[finding.get("severity", "info")] += 1
                ui.label("Dashboard").classes("text-2xl font-semibold")
                ui.label("A quiet, local view of your saved reconnaissance work.").classes("ns-muted")
                with ui.row().classes("w-full flex-wrap gap-3"):
                    for label, value, color in (("Saved scans", len(rows), "#35b8e8"), ("Alive hosts", alive, "#42d392"), ("Open ports", open_ports, "#35b8e8"), ("Service observations", services, "#f2b84b")):
                        with ui.card().classes("ns-card min-w-[170px] flex-1"):
                            ui.label(label).classes("ns-kicker")
                            ui.label(str(value)).classes("text-3xl font-semibold").style(f"color:{color}")
                with ui.row().classes("w-full items-stretch gap-4 flex-wrap"):
                    with ui.card().classes("ns-card flex-1 min-w-[260px]"):
                        ui.label("Findings by severity").classes("font-semibold mb-3")
                        if severity:
                            for level in ("high", "medium", "low", "info"):
                                with ui.row().classes("w-full justify-between py-1"):
                                    ui.label(level.title()).classes("ns-muted")
                                    ui.label(str(severity.get(level, 0))).classes("ns-mono")
                        else:
                            ui.label("No findings yet. Open ports remain observations until evidence supports a finding.").classes("ns-muted text-sm")
                    with ui.card().classes("ns-card flex-[2] min-w-[320px]"):
                        ui.label("Recent scans").classes("font-semibold mb-3")
                        if rows:
                            for row in rows[:5]:
                                with ui.row().classes("w-full justify-between items-center border-b border-[#263a5b] py-2"):
                                    ui.label(row["target"]).classes("ns-mono")
                                    ui.label(f"{row['started_at']} · {row['status']}").classes("ns-muted text-xs")
                        else:
                            ui.label("No saved scans. Start a scan to populate this workspace.").classes("ns-muted text-sm")
                if errors:
                    ui.label(f"{len(errors)} saved report(s) could not be read; see Reports for details.").classes("text-[#f2b84b] text-sm")
                if live.status in {"running", "cancelling"}:
                    ui.label(f"Running scan · {live.phase or 'starting'} · {live.progress:.0%}").classes("text-[#35b8e8] text-sm")
            dashboard()

        with ui.column() as new_section:
            sections["new"] = new_section
            ui.label("New scan").classes("text-2xl font-semibold")
            ui.label("Define a bounded, authorized IPv4 assessment.").classes("ns-muted")
            with ui.card().classes("ns-card w-full"):
                form = ScanForm(output_directory=str(output_root), timeout=settings.get("timeout", 1.5), workers=settings.get("workers", 200), reverse_dns=bool(settings.get("reverse_dns", True)), banner_inspection=bool(settings.get("banner_inspection", True)), profile=str(settings.get("default_profile", "standard")))
                inputs: dict[str, Any] = {}
                error_labels: dict[str, Any] = {}
                with ui.grid(columns=2).classes("w-full gap-4"):
                    inputs["target"] = ui.input("Target", placeholder="192.168.1.0/24 or example.com").props("outlined clearable")
                    inputs["profile"] = ui.select({"quick": "Quick · curated 100 ports", "standard": "Standard · ports 1–1000", "full": "Full · ports 1–65535", "custom": "Custom"}, value=form.profile, label="Scan profile").props("outlined")
                    inputs["discovery_method"] = ui.select({"auto": "Auto", "icmp": "ICMP", "arp": "ARP (direct LAN + privilege)", "dns": "DNS (domain targets)"}, value=form.discovery_method, label="Discovery method").props("outlined")
                    inputs["ports"] = ui.input("Ports", value=form.ports, placeholder="22,80,443 or 8000-8100").props("outlined")
                    inputs["timeout"] = ui.number("Timeout (seconds)", value=form.timeout, min=0.01, max=120, step=0.1).props("outlined")
                    inputs["workers"] = ui.number("Workers", value=form.workers, min=1, max=1024, step=1).props("outlined")
                    inputs["rate_limit"] = ui.number("Rate limit (probes/second)", value=form.rate_limit, min=0.1, max=100000, step=1).props("outlined hint=optional")
                    inputs["output_directory"] = ui.input("Output location", value=form.output_directory).props("outlined")
                for key in ("target", "profile", "discovery_method", "ports", "timeout", "workers", "rate_limit", "output_directory"):
                    error_labels[key] = ui.label().classes("text-[#ff6b75] text-xs")
                with ui.row().classes("gap-6 flex-wrap mt-2"):
                    inputs["reverse_dns"] = ui.checkbox("Reverse DNS", value=form.reverse_dns)
                    inputs["banner_inspection"] = ui.checkbox("Banner inspection", value=form.banner_inspection)
                    inputs["subdomain_enumeration"] = ui.checkbox("Subdomain enumeration", value=form.subdomain_enumeration)
                inputs["output_formats"] = ui.select(["json", "text", "html"], value=form.output_formats, label="Output formats", multiple=True).props("outlined use-chips")
                error_labels["output_formats"] = ui.label().classes("text-[#ff6b75] text-xs")
                with ui.row().classes("items-center gap-2 mt-3"):
                    inputs["authorization_confirmed"] = ui.checkbox("I have authorization to assess this target and will use the results responsibly.")
                error_labels["authorization_confirmed"] = ui.label().classes("text-[#ff6b75] text-xs")
                ui.separator().classes("my-4")
                scan_button = ui.button("Start scan", icon="play_arrow").props("unelevated color=primary no-caps")
                validation_summary = ui.label().classes("text-[#ff6b75] text-sm ml-3")

                def read_form() -> ScanForm:
                    values = {key: (value.value if hasattr(value, "value") else value) for key, value in inputs.items()}
                    values["output_formats"] = _normalize_output_formats(values.get("output_formats"))
                    return ScanForm(**values)

                def validate_view() -> None:
                    candidate = read_form()
                    errors = validate_scan_form(candidate)
                    for key, label in error_labels.items():
                        label.set_text(errors.get(key, ""))
                        label.set_visibility(key in errors)
                    scan_button.enabled = not errors
                    validation_summary.set_text("Fix the highlighted fields before starting." if errors else "Ready to scan.")
                    validation_summary.classes(remove="text-[#ff6b75]", add="text-[#42d392]" if not errors else "text-[#ff6b75]")

                for element in inputs.values():
                    if hasattr(element, "on"):
                        element.on("update:model-value", lambda _: validate_view())
                        element.on("change", lambda _: validate_view())
                validate_view()

        with ui.column() as live_section:
            sections["live"] = live_section
            ui.label("Live scan").classes("text-2xl font-semibold")
            ui.label("Events are streamed from the engine without touching the UI from worker threads.").classes("ns-muted")
            with ui.card().classes("ns-card w-full"):
                live_phase = ui.label("No scan running").classes("text-lg")
                live_progress = ui.linear_progress(value=0).classes("w-full mt-3")
                with ui.row().classes("gap-8 mt-4 flex-wrap"):
                    live_host_count = ui.label("Hosts discovered: 0")
                    live_port_count = ui.label("Open ports: 0")
                    live_elapsed = ui.label("Elapsed: 0s")
                live_current = ui.label("Current task: —").classes("ns-mono ns-muted mt-2")
                live_log = ui.log(max_lines=200).classes("w-full h-64 mt-4 bg-[#0a101b]")
                cancel_button = ui.button("Cancel scan", icon="stop", on_click=lambda: cancel_scan()).props("outline color=negative no-caps")
                final_state = ui.label().classes("mt-3")

        with ui.column() as assets_section:
            sections["assets"] = assets_section
            @ui.refreshable
            def assets():
                ui.label("Assets").classes("text-2xl font-semibold")
                ui.label("Latest observations are merged by IPv4 address.").classes("ns-muted")
                paths, _ = _report_files(output_root)
                observations = []
                for path in paths:
                    try:
                        observations.append(load_report(str(path)))
                    except ReportError:
                        pass
                rows = aggregate_assets(observations)
                search = ui.input("Search assets", placeholder="IP, hostname, vendor, OS, or risk").props("outlined clearable").classes("w-full max-w-xl mb-3")
                columns = [{"name": "ip", "label": "IP address", "field": "ip", "sortable": True}, {"name": "hostname", "label": "Hostname", "field": "hostname", "sortable": True}, {"name": "mac", "label": "MAC", "field": "mac"}, {"name": "vendor", "label": "Vendor", "field": "vendor", "sortable": True}, {"name": "os", "label": "OS guess", "field": "os", "sortable": True}, {"name": "confidence", "label": "Confidence", "field": "confidence"}, {"name": "open_ports", "label": "Open ports", "field": "open_ports", "sortable": True}, {"name": "highest_risk", "label": "Highest risk", "field": "highest_risk", "sortable": True}, {"name": "last_seen", "label": "Last seen", "field": "last_seen", "sortable": True}]
                table = ui.table(columns=columns, rows=[{key: value for key, value in row.items() if key != "report"} for row in rows], row_key="ip", pagination={"rowsPerPage": 15}).classes("w-full ns-card")
                table.bind_filter_from(search, "value")
                table.on("rowClick", lambda event: host_detail(next((row for row in rows if row["ip"] == event.args[1].get("ip")), None)))
                if not rows:
                    ui.label("No alive hosts in saved reports yet.").classes("ns-muted mt-3")

        with ui.column() as reports_section:
            sections["reports"] = reports_section
            @ui.refreshable
            def reports():
                ui.label("Reports").classes("text-2xl font-semibold")
                ui.label("Open, download, or delete individual saved reports.").classes("ns-muted")
                rows, errors = _report_rows(output_root)
                if errors:
                    ui.label("Some report files could not be opened:").classes("text-[#f2b84b] mt-3")
                    for error in errors[:10]:
                        ui.label(error).classes("text-[#f2b84b] text-xs ns-mono")
                columns = [{"name": "target", "label": "Target", "field": "target", "sortable": True}, {"name": "status", "label": "Status", "field": "status", "sortable": True}, {"name": "started_at", "label": "Started", "field": "started_at", "sortable": True}, {"name": "hosts", "label": "Hosts", "field": "hosts", "sortable": True}, {"name": "actions", "label": "Actions", "field": "actions"}]
                table = ui.table(columns=columns, rows=rows, row_key="scan_id", pagination={"rowsPerPage": 15}).classes("w-full ns-card")
                table.add_slot("body-cell-actions", '<q-td :props="props"><q-btn flat dense label="Open" @click="$parent.$emit(\'open\', props.row)" /></q-td>')
                table.on("open", lambda event: open_report(event.args))
                if not rows:
                    ui.label("No saved reports yet.").classes("ns-muted mt-3")

        with ui.column() as compare_section:
            sections["compare"] = compare_section
            @ui.refreshable
            def compare():
                ui.label("Compare").classes("text-2xl font-semibold")
                ui.label("Compare two completed JSON reports with compatible coverage.").classes("ns-muted")
                rows, _ = _report_rows(output_root)
                options = {row["path"]: f"{row['started_at']} · {row['target']}" for row in rows}
                before = ui.select(options, label="Earlier report").props("outlined").classes("w-full max-w-xl")
                after = ui.select(options, label="Later report").props("outlined").classes("w-full max-w-xl")
                result_box = ui.column().classes("w-full")
                def do_compare():
                    result_box.clear()
                    if not before.value or not after.value:
                        ui.notify("Select two reports first", type="warning")
                        return
                    try:
                        result = compare_report_files(str(before.value), str(after.value))
                    except ReportError as exc:
                        with result_box:
                            ui.label(str(exc)).classes("text-[#ff6b75]")
                        return
                    with result_box:
                        ui.label("Compatible" if result.get("compatible") else "Indeterminate").classes("text-[#42d392]" if result.get("compatible") else "text-[#f2b84b]")
                        ui.code(json.dumps(result, indent=2), language="json").classes("w-full")
                ui.button("Compare reports", icon="compare_arrows", on_click=do_compare).props("unelevated color=primary no-caps")

        with ui.column() as settings_section:
            sections["settings"] = settings_section
            ui.label("Settings").classes("text-2xl font-semibold")
            ui.label("Stored locally in your user config directory; no secrets are saved.").classes("ns-muted")
            with ui.card().classes("ns-card w-full max-w-2xl"):
                theme = ui.select({"dark": "Dark", "light": "Light"}, value=settings.get("theme", "dark"), label="Theme").props("outlined")
                profile = ui.select({"quick": "Quick", "standard": "Standard", "full": "Full"}, value=settings.get("default_profile", "standard"), label="Default profile").props("outlined")
                timeout = ui.number("Default timeout", value=settings.get("timeout", 1.5), min=0.01, max=120, step=.1).props("outlined")
                workers = ui.number("Default workers", value=settings.get("workers", 200), min=1, max=1024, step=1).props("outlined")
                rate = ui.number("Default rate limit", value=settings.get("rate_limit"), min=.1, max=100000, step=1).props("outlined")
                output = ui.input("Default output directory", value=settings.get("output_directory", "output")).props("outlined")
                rdns = ui.checkbox("Reverse DNS by default", value=bool(settings.get("reverse_dns", True)))
                banner = ui.checkbox("Banner inspection by default", value=bool(settings.get("banner_inspection", True)))
                setting_status = ui.label().classes("ns-muted text-sm")
                def save():
                    nonlocal output_root
                    try:
                        new_output_root = _resolve_output_directory(str(output.value))
                        validate_output_dir(str(new_output_root), create=True)
                        output_root = new_output_root
                        output.value = str(output_root)
                        save_settings({"theme": theme.value, "default_profile": profile.value, "timeout": timeout.value, "workers": workers.value, "rate_limit": rate.value, "output_directory": str(output.value), "reverse_dns": rdns.value, "banner_inspection": banner.value})
                        setting_status.set_text("Saved locally.")
                        dashboard.refresh()
                    except (ValidationError, OSError) as exc:
                        setting_status.set_text(str(exc))
                        setting_status.classes(remove="text-[#42d392]", add="text-[#ff6b75]")
                ui.button("Save settings", icon="save", on_click=save).props("unelevated color=primary no-caps")

        def host_detail(row):
            if not row:
                return
            report = row.get("report") or {}
            ip = row.get("ip")
            with ui.dialog() as dialog, ui.card().classes("ns-card w-[min(900px,95vw)] max-h-[85vh]"):
                ui.label(f"Host detail · {ip}").classes("text-xl font-semibold")
                ui.label(f"{row.get('hostname', '-')} · {row.get('mac', '-')} · {row.get('vendor', '-')}").classes("ns-muted")
                ui.code(json.dumps({"host": next((host for host in report.get("hosts", []) if host.get("ip") == ip), {}), "ports": (report.get("port_results") or {}).get(ip, []), "services": (report.get("service_guesses") or {}).get(ip, []), "os": (report.get("os_guesses") or {}).get(ip, {}), "http": {key: value for key, value in (report.get("http_results") or {}).items() if key.startswith(f"{ip}:")}, "tls": {key: value for key, value in (report.get("tls_results") or {}).items() if key.startswith(f"{ip}:")}, "findings": [finding for finding in report.get("findings", []) if finding.get("host") == ip]}, indent=2, ensure_ascii=False), language="json").classes("w-full overflow-auto")
                ui.button("Close", on_click=dialog.close).props("flat no-caps")
            dialog.open()

        def open_report(row):
            if not row:
                return
            try:
                report = load_report(row["path"])
            except ReportError as exc:
                ui.notify(str(exc), type="negative")
                return
            scan_id = str((report.get("meta") or {}).get("scan_id") or "netscope-report")
            json_payload = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
            text_payload = render_text(report).encode("utf-8")
            html_payload = render_html(report).encode("utf-8")
            with ui.dialog() as dialog, ui.card().classes("ns-card w-[min(1100px,96vw)] max-h-[90vh]"):
                ui.label(f"Report · {report.get('meta', {}).get('target', '?')}").classes("text-xl font-semibold")
                with ui.tabs() as tabs:
                    json_tab = ui.tab("JSON")
                    text_tab = ui.tab("Text")
                    html_tab = ui.tab("HTML")
                with ui.tab_panels(tabs, value=json_tab).classes("w-full"):
                    with ui.tab_panel(json_tab):
                        ui.code(json.dumps(report, indent=2, ensure_ascii=False), language="json").classes("w-full max-h-[60vh]")
                    with ui.tab_panel(text_tab):
                        ui.code(render_text(report), language="text").classes("w-full max-h-[60vh]")
                    with ui.tab_panel(html_tab):
                        ui.html(render_html(report), sanitize=False).classes("w-full max-h-[60vh] overflow-auto")
                with ui.row().classes("justify-between w-full"):
                    ui.button("Download JSON", on_click=lambda: ui.download(json_payload, filename=f"{scan_id}.json", media_type="application/json")).props("flat no-caps")
                    ui.button("Download text", on_click=lambda: ui.download(text_payload, filename=f"{scan_id}.txt", media_type="text/plain")).props("flat no-caps")
                    ui.button("Download HTML", on_click=lambda: ui.download(html_payload, filename=f"{scan_id}.html", media_type="text/html")).props("flat no-caps")
                    ui.button("Delete…", on_click=lambda: confirm_delete(row, dialog)).props("outline color=negative no-caps")
                    ui.button("Close", on_click=dialog.close).props("flat no-caps")
            dialog.open()

        def confirm_delete(row, parent_dialog):
            with ui.dialog() as confirm, ui.card().classes("ns-card"):
                ui.label("Delete this saved report?").classes("text-lg")
                ui.label("This removes only the selected report bundle from the configured output directory.").classes("ns-muted text-sm")
                with ui.row():
                    ui.button("Cancel", on_click=confirm.close).props("flat no-caps")
                    def remove():
                        try:
                            path = Path(row["path"]).resolve()
                            root = output_root.resolve()
                            if root not in path.parents:
                                raise OSError("report is outside the configured output directory")
                            for sibling in path.parent.glob("report.*"):
                                sibling.unlink(missing_ok=True)
                            confirm.close(); parent_dialog.close(); reports.refresh(); dashboard.refresh(); ui.notify("Report deleted", type="positive")
                        except OSError as exc:
                            ui.notify(str(exc), type="negative")
                    ui.button("Delete report", on_click=remove).props("unelevated color=negative no-caps")
            confirm.open()

        def cancel_scan():
            if cancellation is not None and live.status in {"running", "cancelling"}:
                live.cancel_requested(); cancellation.cancel(); cancel_button.disable(); final_state.set_text("Cancellation requested; finishing in-flight probes…")

        async def start_scan():
            nonlocal cancellation, current_result
            candidate = read_form()
            errors = validate_scan_form(candidate)
            if errors:
                validate_view(); switch("new"); return
            try:
                candidate.output_directory = str(_resolve_output_directory(candidate.output_directory))
                validate_output_dir(candidate.output_directory, create=True)
            except ValidationError as exc:
                error_labels["output_directory"].set_text(str(exc)); error_labels["output_directory"].set_visibility(True); return
            if live.status in {"running", "cancelling"}:
                ui.notify("A scan is already running", type="warning"); return
            request = candidate.to_request()
            cancellation = CancellationToken(); current_result = None; live.start(); cancel_button.enable(); final_state.set_text(""); switch("live")
            while not event_queue.empty():
                try: event_queue.get_nowait()
                except queue.Empty: break
            try:
                current_result = await run.io_bound(_run_engine, request, cancellation, event_queue)
                if current_result and current_result.report:
                    dashboard.refresh(); reports.refresh(); assets.refresh(); compare.refresh()
                message = {"completed": "Scan completed successfully.", "cancelled": "Scan cancelled; partial results were preserved.", "failed": "Scan failed: " + "; ".join(current_result.errors)}.get(current_result.status, current_result.status)
                if current_result.status == "completed" and request.output_directory:
                    message += f" Reports saved in {request.output_directory}"
                final_state.set_text(message)
            except Exception as exc:
                live.status = "failed"; live.error = str(exc); final_state.set_text(f"Scan failed: {exc}")
            finally:
                cancel_button.disable(); cancellation = None

        scan_button.on_click(start_scan)

        def drain_events():
            changed = False
            while True:
                try: event = event_queue.get_nowait()
                except queue.Empty: break
                live.apply(event); live_phase.set_text(f"{live.phase or 'starting'} · {live.status}"); live_progress.set_value(live.progress); live_host_count.set_text(f"Hosts discovered: {live.hosts_discovered}"); live_port_count.set_text(f"Open ports: {live.open_ports}"); live_current.set_text(f"Current task: {live.current_host or '—'}")
                live_elapsed.set_text(f"Elapsed: {live.elapsed_seconds:.1f}s")
                if event.message: live_log.push(event.message)
                changed = True
            if live.started_monotonic is not None and live.status in {"running", "cancelling"}:
                live.elapsed_seconds = time.monotonic() - live.started_monotonic; live_elapsed.set_text(f"Elapsed: {live.elapsed_seconds:.1f}s")
            return changed

        ui.timer(0.1, drain_events)
        for key, container in sections.items():
            container.set_visibility(key == "dashboard")


def main(*, host: str = "127.0.0.1", port: int = 8080) -> int:
    if ui is None:
        print("NiceGUI is not installed; install requirements.txt first", file=__import__("sys").stderr)
        return 1
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("NetScope UI binds to loopback only by default")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port must be between 1 and 65535")
    try:
        ui.run(build_app, host=host, port=int(port), native=False, reload=False, title=f"NetScope v{__version__}", dark=True, show=False, uvicorn_logging_level="warning")
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

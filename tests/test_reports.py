from pathlib import Path

from modules.comparison import compare_reports
from modules.exporter import build_report, render_html, write_outputs
from modules.ping_sweep import Host
from modules.port_scanner import PortResult


def _report(port=80, banner="safe"):
    return build_report(target="192.0.2.1", hosts=[Host("192.0.2.1", alive=True)], port_results={"192.0.2.1": [PortResult("192.0.2.1", port, open=True, state="open", banner=banner)]}, service_guesses={}, os_guesses={}, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z", coverage={"discovery_complete": True, "requested_ports": [80, 443], "completed_ports_by_host": {"192.0.2.1": 2}})


def test_output_formats_are_exact():
    report = _report()
    output = Path("test-output-formats")
    output.mkdir(exist_ok=True)
    for path in output.glob("report.*"):
        path.unlink()
    write_outputs(report, str(output), "text")
    assert (output / "report.txt").exists() and not (output / "report.json").exists()
    write_outputs(report, str(output), "json")
    assert (output / "report.json").exists()
    for path in output.glob("report.*"):
        path.unlink()
    output.rmdir()


def test_output_format_lists_support_ui_combinations():
    report = _report()
    output = Path("test-output-format-list")
    output.mkdir(exist_ok=True)
    try:
        write_outputs(report, str(output), ["json", "html"])
        assert (output / "report.json").exists() and (output / "report.html").exists()
        assert not (output / "report.txt").exists()
    finally:
        for path in output.glob("report.*"):
            path.unlink()
        output.rmdir()


def test_html_escapes_network_data():
    rendered = render_html(_report(banner="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_report_comparison_detects_port_changes():
    before = _report(80)
    after = _report(443)
    result = compare_reports(before, after)
    assert result["compatible"]
    assert ["192.0.2.1", 443] in result["opened_ports"]
    assert ["192.0.2.1", 80] in result["closed_ports"]

from modules.engine import ScanEvent
from modules.ui_state import LiveScanState, ScanForm, validate_scan_form


def test_form_validation_is_field_specific():
    errors = validate_scan_form(ScanForm(target="", authorization_confirmed=False))
    assert "target" in errors and "authorization_confirmed" in errors
    ready = ScanForm(target="192.0.2.1", profile="custom", ports="80", authorization_confirmed=True)
    assert validate_scan_form(ready) == {}
    text_only = ScanForm(target="192.0.2.1", profile="custom", ports="80", output_formats=["text"], authorization_confirmed=True)
    assert "output_formats" in validate_scan_form(text_only)


def test_live_state_transitions():
    state = LiveScanState()
    state.apply(ScanEvent("scan_started", "2026-01-01T00:00:00Z", message="started"))
    state.apply(ScanEvent("host_discovered", "2026-01-01T00:00:00Z", host="192.0.2.1", message="host"))
    state.apply(ScanEvent("port_opened", "2026-01-01T00:00:00Z", host="192.0.2.1", port=80, message="port"))
    assert state.status == "running" and state.hosts_discovered == 1 and state.open_ports == 1
    state.apply(ScanEvent("scan_cancelled", "2026-01-01T00:00:00Z", progress=1, message="cancelled"))
    assert state.status == "cancelled"

from pathlib import Path

import pytest

from modules.engine import ScanEngine, ScanRequest
from modules.exporter import ReportError, load_report
from modules.ping_sweep import PrivilegeUnavailable, ping_sweep
from modules.subdomain_enum import load_wordlist
from modules.utils import ValidationError


def test_engine_rejects_invalid_request_before_io():
    with pytest.raises(ValidationError):
        ScanEngine().validate_request(ScanRequest(target="127.0.0.1", workers=0))
    with pytest.raises(ValidationError):
        ScanEngine().validate_request(ScanRequest(target="127.0.0.1", timeout=float("nan")))
    with pytest.raises(ValidationError):
        ScanEngine().validate_request(ScanRequest(target="127.0.0.1", profile="custom", ports="0"))


def test_explicit_arp_reports_privilege_unavailable(monkeypatch):
    monkeypatch.setattr("modules.ping_sweep.arp_available", lambda targets: (False, "test privilege unavailable"))
    with pytest.raises(PrivilegeUnavailable, match="privilege unavailable"):
        ping_sweep("192.0.2.1", method="arp")


def test_corrupt_and_unknown_reports_are_typed_errors():
    root = Path("test-error-temp")
    root.mkdir(exist_ok=True)
    try:
        corrupt = root / "corrupt.json"
        corrupt.write_text("not json", encoding="utf-8")
        with pytest.raises(ReportError):
            load_report(str(corrupt))
        unknown = root / "unknown.json"
        unknown.write_text('{"schema_version": 99, "meta": {}}', encoding="utf-8")
        with pytest.raises(ReportError, match="unsupported"):
            load_report(str(unknown))
    finally:
        for path in root.glob("*"):
            path.unlink()
        root.rmdir()


def test_default_subdomain_wordlist_has_no_filesystem_side_effect(monkeypatch):
    monkeypatch.setattr("modules.subdomain_enum.default_wordlist_path", lambda: "should-not-exist.txt")
    assert load_wordlist(None)

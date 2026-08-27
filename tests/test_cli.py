import pytest

import scanner
from modules import __version__
from modules.utils import ValidationError


def test_scan_cli_keeps_custom_ports_by_default():
    parser = scanner.build_parser()
    args = parser.parse_args(["scan", "127.0.0.1", "--ports", "443"])
    assert args.profile == "custom"
    request = scanner._request_from_args(args, "scan")
    assert request.ports == [443]


def test_scan_cli_rejects_invalid_port_before_any_probe():
    parser = scanner.build_parser()
    args = parser.parse_args(["scan", "127.0.0.1", "--ports", "0"])
    with pytest.raises(ValidationError):
        scanner._request_from_args(args, "scan")


def test_cli_exposes_project_version(capsys):
    with pytest.raises(SystemExit) as exc:
        scanner.build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert __version__ == "2.0.0"
    assert "netscope 2.0.0" in capsys.readouterr().out

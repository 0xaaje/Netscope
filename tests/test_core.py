from unittest.mock import Mock

import pytest

from modules.ping_sweep import Host, _icmp_probe, _directly_connected_ipv4
from modules.port_scanner import _probe_for
from modules.service_detect import OSGuess, detect_os, detect_services
from modules.port_scanner import PortResult


def test_banner_probe_uses_string_service_hints():
    assert _probe_for(80)[0] == "http"
    assert _probe_for(25)[0] == "smtp"
    assert _probe_for(22)[0] == "ssh"


def test_service_capture_groups_are_extracted():
    guesses = detect_services([PortResult(host="127.0.0.1", port=22, open=True, banner="SSH-2.0-OpenSSH_9.6p1")])
    assert guesses[0].version == "9.6p1"
    guesses = detect_services([PortResult(host="127.0.0.1", port=80, open=True, banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu)")])
    assert guesses[0].version == "2.4.58"
    assert guesses[0].extra == "Ubuntu"


def test_ttl_is_captured_and_does_not_downgrade_strong_banner(monkeypatch):
    proc = Mock(returncode=0, stdout="64 bytes from 127.0.0.1: ttl=128 time=0.4 ms\n")
    monkeypatch.setattr("modules.ping_sweep.subprocess.run", lambda *args, **kwargs: proc)
    monkeypatch.setattr("modules.ping_sweep._ping_cmd", lambda ip: ["ping", ip])
    host = _icmp_probe("127.0.0.1", 1)
    assert host.alive and host.ttl == 128 and host.rtt_ms == 0.4
    guess = detect_os([PortResult(host="127.0.0.1", port=22, open=True, banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu")], ttl_observed=128)
    assert guess.family == "Linux"
    assert guess.confidence == "high"

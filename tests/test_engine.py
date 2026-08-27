from modules.engine import CancellationToken, ScanEngine, ScanRequest
from modules.ping_sweep import Host
from modules.port_scanner import PortResult
from modules.subdomain_enum import SubdomainHit


def test_domain_all_resolves_and_enumerates(monkeypatch):
    monkeypatch.setattr("modules.engine.enumerate_subdomains", lambda *args, **kwargs: [SubdomainHit("www.example.com", "active", ["192.0.2.10"], True)])
    def fake_port_scan(host, ports, **kwargs):
        callback = kwargs["on_result"]
        result = PortResult(host=host, port=80, open=True, state="open", banner="HTTP/1.1 200 OK")
        callback(result)
        return [result]
    monkeypatch.setattr("modules.engine.port_scan", fake_port_scan)
    events = []
    request = ScanRequest(target="Example.com", operation="all", profile="custom", ports=[80], reverse_dns=False)
    result = ScanEngine(resolver=lambda domain: [(2, 1, 6, "", ("192.0.2.10", 0))]).run(request, event_sink=events.append)
    assert result.status == "completed"
    assert [host.ip for host in result.hosts] == ["192.0.2.10"]
    assert result.subdomains[0].subdomain == "www.example.com"
    assert {event.type for event in events} >= {"scan_started", "phase_started", "host_discovered", "port_opened", "scan_finished"}


def test_cancelled_scan_preserves_partial_results(monkeypatch):
    token = CancellationToken()
    def fake_ping(*args, **kwargs):
        host = Host("127.0.0.1", alive=True, method="icmp")
        kwargs["on_result"](host)
        token.cancel()
        return [host]
    monkeypatch.setattr("modules.engine.ping_sweep", fake_ping)
    request = ScanRequest(target="127.0.0.1", operation="scan", profile="custom", ports=[80], reverse_dns=False)
    result = ScanEngine().run(request, cancellation=token)
    assert result.status == "cancelled"
    assert result.hosts and result.report["meta"]["status"] == "cancelled"
    assert result.report["coverage"]["discovery_complete"] is False

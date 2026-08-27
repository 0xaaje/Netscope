import math

import pytest

from modules.utils import ValidationError, TOP_1000_PORTS, TOP_100_PORTS, normalize_domain, parse_ports, parse_targets, validate_timeout, validate_workers


def test_target_parsing_and_ipv6_rejection():
    assert parse_targets("192.168.1.1,192.168.1.1,192.168.1.3-192.168.1.4") == ["192.168.1.1", "192.168.1.3", "192.168.1.4"]
    with pytest.raises(ValidationError, match="IPv6"):
        parse_targets("2001:db8::1")
    with pytest.raises(ValidationError):
        parse_targets("192.168.1.1,")


def test_domains_and_presets():
    assert normalize_domain("My-Site.Example.COM.") == "my-site.example.com"
    with pytest.raises(ValidationError):
        normalize_domain("bad..example.com")
    assert len(TOP_100_PORTS) == len(set(TOP_100_PORTS)) == 100
    assert len(TOP_1000_PORTS) == len(set(TOP_1000_PORTS)) == 1000
    assert parse_ports("top100") == TOP_100_PORTS
    assert parse_ports("top1000") == TOP_1000_PORTS
    with pytest.raises(ValidationError):
        parse_ports("")
    with pytest.raises(ValidationError):
        parse_ports("0,80")


def test_numeric_validation():
    assert validate_timeout(1.5) == 1.5
    with pytest.raises(ValidationError):
        validate_timeout(math.inf)
    with pytest.raises(ValidationError):
        validate_workers(0)

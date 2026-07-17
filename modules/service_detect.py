"""NetScope - OS & service version detection from banners.

This is a *lightweight* detector — not nmap. It does not send crafted
probes; it parses the banner strings we already grabbed and matches
them against a curated set of regexes. The output is a best-effort
guess with a confidence level. False positives are easy, so the report
flags every guess as such.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Sequence

from .port_scanner import PortResult
from .utils import dim, yellow


# --- Data types -------------------------------------------------------------

@dataclass
class ServiceGuess:
    port: int
    product: str
    version: Optional[str] = None
    extra: Optional[str] = None
    confidence: str = "low"  # "high" | "medium" | "low"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OSGuess:
    family: str
    version: Optional[str] = None
    device: Optional[str] = None
    confidence: str = "low"
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- Service detection rules ------------------------------------------------

# Each rule: (port-or-None, regex-on-banner, product, version-group, extra-group)
# A None port means "applies to any port". Confidence: high if the regex
# captures a version + vendor, medium if just product, low otherwise.
_SERVICE_RULES: list = [
    # SSH
    (22, r"OpenSSH[_\- ]([0-9][0-9p.\-]+)",                 "OpenSSH",     1, None, "high"),
    (22, r"SSH-2\.0-(?:OpenSSH_[0-9p.\-]+|libssh[_-]([0-9.\-]+)|dropbear[_\- ]?([0-9.\-]+))",
                                                              "SSH",         0, None, "high"),
    (22, r"dropbear[_\- ]?([0-9.\-]+)",                     "Dropbear SSH", 1, None, "high"),

    # HTTP servers
    (80, r"Server:\s*Apache/([0-9.]+)(?:\s+\(([^)]+)\))?",  "Apache httpd", 1, 2, "high"),
    (80, r"Server:\s*nginx/([0-9.]+)",                      "nginx",        1, None, "high"),
    (80, r"Server:\s*microsoft-IIS/([0-9.]+)",              "Microsoft IIS",1, None, "high"),
    (80, r"Server:\s*lighttpd/([0-9.]+)",                   "lighttpd",     1, None, "high"),
    (80, r"Server:\s*Apache-Coyote/([0-9.]+)",              "Tomcat",       1, None, "medium"),
    (80, r"Server:\s*gunicorn/([0-9.]+)",                   "gunicorn",     1, None, "medium"),
    (80, r"Server:\s*uvicorn",                             "uvicorn",      None, None, "low"),
    (80, r"Server:\s*werkzeug/([0-9.]+)",                   "Werkzeug",     1, None, "medium"),
    (None, r"Server:\s*([A-Za-z][A-Za-z0-9.\-]+)/([0-9.]+)", "HTTP Server",  1, 2, "medium"),

    # FTP
    (21, r"vsftpd ([0-9.]+)",                               "vsftpd",       1, None, "high"),
    (21, r"ProFTPD ([0-9.]+)",                              "ProFTPD",      1, None, "high"),
    (21, r"FileZilla Server ([0-9.]+)",                     "FileZilla",    1, None, "high"),
    (21, r"Pure-FTPd",                                     "Pure-FTPd",    None, None, "medium"),
    (21, r"Microsoft FTP Service",                          "Microsoft FTP", None, None, "medium"),

    # SMTP
    (25, r"220[ -].*?ESMTP\s+Postfix",                      "Postfix",      None, None, "high"),
    (25, r"220[ -].*?Sendmail ([0-9.]+)",                   "Sendmail",     1, None, "high"),
    (25, r"220[ -].*?Exim ([0-9.]+)",                       "Exim",         1, None, "high"),
    (25, r"220[ -].*?Microsoft ESMTP",                      "Microsoft SMTP", None, None, "medium"),
    (25, r"220[ -].*ESMTP",                                 "SMTP",         None, None, "low"),

    # Databases
    (3306, r"([0-9.]+)-MariaDB",                            "MariaDB",      1, None, "high"),
    (3306, r"([0-9.]+)-log",                                "MySQL",        1, None, "high"),
    (5432, r"PostgreSQL ([0-9.]+)",                         "PostgreSQL",   1, None, "high"),
    (6379, r"-ERR unknown command 'PING'",                  "Redis",        None, None, "high"),
    (6379, r"\+PONG",                                       "Redis",        None, None, "high"),
    (27017, r"It seems like you are trying to access MongoDB over HTTP",
                                                              "MongoDB",      None, None, "high"),
    (11211, r"VERSION ([0-9.]+)",                           "Memcached",    1, None, "high"),
    (9200, r"\"version\"\s*:\s*\{\s*\"number\"\s*:\s*\"([0-9.]+)\"",
                                                              "Elasticsearch", 1, None, "high"),

    # SMB / Windows
    (445, r"Windows",                                       "SMB",          None, None, "low"),

    # RDP
    (3389, r"",                                              "RDP",          None, None, "low"),
]


# --- OS detection rules (TCP/IP fingerprinting without raw sockets) -------

# Source of truth is the banner (server string, SSH version, etc.) plus,
# optionally, the TTL we observed during the ICMP sweep (Linux ~64,
# Windows ~128, network devices ~255).  None of these are authoritative;
# they narrow the field but the report must say so.

@dataclass
class OsEvidence:
    ttl: Optional[int] = None
    banners: list = field(default_factory=list)


_OS_FINGERPRINTS = [
    # Linux family
    (r"Ubuntu",                 "Linux",   "Ubuntu",      "high"),
    (r"Debian",                 "Linux",   "Debian",      "high"),
    (r"CentOS",                 "Linux",   "CentOS",      "high"),
    (r"Red Hat",                "Linux",   "Red Hat",     "high"),
    (r"Fedora",                 "Linux",   "Fedora",      "high"),
    (r"Amazon Linux",           "Linux",   "Amazon Linux", "high"),
    (r"openSUSE",               "Linux",   "openSUSE",    "high"),
    (r"Alpine",                 "Linux",   "Alpine",      "high"),
    (r"GNU/Linux",              "Linux",   "Linux",       "medium"),
    (r"Linux",                  "Linux",   "Linux",       "low"),
    # BSD family
    (r"FreeBSD",                "BSD",     "FreeBSD",     "high"),
    (r"OpenBSD",                "BSD",     "OpenBSD",     "high"),
    (r"NetBSD",                 "BSD",     "NetBSD",      "high"),
    # Windows
    (r"Windows",                "Windows", "Windows",     "high"),
    (r"Microsoft",              "Windows", "Windows",     "medium"),
    (r"IIS",                    "Windows", "Windows",     "medium"),
    # Network / appliance
    (r"Cisco",                  "Network", "Cisco IOS",   "high"),
    (r"Juniper",                "Network", "Juniper",     "high"),
    (r"MikroTik",               "Network", "MikroTik",    "high"),
    # Apple
    (r"Darwin",                 "macOS",   "macOS",       "high"),
    (r"macOS",                  "macOS",   "macOS",       "medium"),
]


# --- Public entry point -----------------------------------------------------

def detect_services(
    port_results: Sequence[PortResult],
    *,
    ttl_observed: Optional[int] = None,
) -> List[ServiceGuess]:
    """Run banner regexes against the open ports."""
    out: List[ServiceGuess] = []
    for pr in port_results:
        if not pr.open or not pr.banner:
            continue
        for rule in _SERVICE_RULES:
            rule_port, regex, product, vgrp, xgrp, conf = rule
            if rule_port is not None and rule_port != pr.port:
                continue
            m = re.search(regex, pr.banner, re.IGNORECASE)
            if not m:
                continue
            version = None
            if vgrp is not None and vgrp < len(m.groups()) and m.group(vgrp):
                version = m.group(vgrp)
            extra = None
            if xgrp is not None and xgrp < len(m.groups()) and m.group(xgrp):
                extra = m.group(xgrp)
            out.append(ServiceGuess(
                port=pr.port,
                product=product,
                version=version,
                extra=extra,
                confidence=conf,
            ))
            break  # one rule per port is enough
    return out


def detect_os(
    port_results: Sequence[PortResult],
    *,
    ttl_observed: Optional[int] = None,
) -> OSGuess:
    """Best-effort OS guess from banners + optional TTL.

    Heuristic: collect every banner that mentions a vendor/OS keyword,
    pick the highest-confidence hit, then bias by TTL if available.
    """
    blobs = " ".join((pr.banner or "") for pr in port_results if pr.open)

    best: Optional[OSGuess] = None
    for regex, family, version, conf in _OS_FINGERPRINTS:
        if re.search(regex, blobs, re.IGNORECASE):
            cand = OSGuess(family=family, version=version, confidence=conf,
                           reason=f"banner matched /{regex}/")
            if best is None or _rank_conf(cand.confidence) > _rank_conf(best.confidence):
                best = cand

    # TTL bias (very weak signal on its own)
    if ttl_observed is not None:
        guess_from_ttl = _os_from_ttl(ttl_observed)
        if best is None:
            best = guess_from_ttl
        elif best and _rank_conf(guess_from_ttl.confidence) > _rank_conf(best.confidence):
            best = guess_from_ttl
        else:
            # Note agreement / disagreement
            if best.family != guess_from_ttl.family:
                best.confidence = "low"
                best.reason += f"; TTL {ttl_observed} suggests {guess_from_ttl.family}"

    if best is None:
        return OSGuess(family="Unknown", confidence="low", reason="no signals")
    return best


# --- helpers ---------------------------------------------------------------

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _rank_conf(c: str) -> int:
    return _CONFIDENCE_RANK.get(c, 0)


def _os_from_ttl(ttl: int) -> OSGuess:
    """Very rough TTL-based guess. Real TTLs are decremented by hops, so
    we bucket in ranges. Network devices usually ship TTL=255, BSD/Linux
    64, Windows 128. Within ±10 of those, we guess the family.
    """
    if 240 <= ttl <= 255:
        return OSGuess(family="Network", device="router/switch",
                       confidence="low", reason=f"ttl={ttl}")
    if 120 <= ttl <= 139:
        return OSGuess(family="Windows", confidence="low", reason=f"ttl={ttl}")
    if 50 <= ttl <= 69:
        return OSGuess(family="Linux/BSD", confidence="low", reason=f"ttl={ttl}")
    return OSGuess(family="Unknown", confidence="low", reason=f"ttl={ttl} (no bucket)")

"""NetScope - shared utilities.

Colored console output, banner, timestamp helpers, target parsing.
Kept stdlib-only on purpose so the rest of the tool can run without pip.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from datetime import datetime, timezone
from typing import Iterable, List, Optional


# --- ANSI color helpers (auto-disable on non-TTY or NO_COLOR) --------------

def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_USE_COLOR = _color_enabled()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t: str) -> str: return _c("31", t)
def green(t: str) -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def blue(t: str) -> str: return _c("34", t)
def magenta(t: str) -> str: return _c("35", t)
def cyan(t: str) -> str: return _c("36", t)
def bold(t: str) -> str: return _c("1", t)
def dim(t: str) -> str: return _c("2", t)


# --- Banner -----------------------------------------------------------------

BANNER = r"""
   _   __     __  _____           _
  | | / /__  / /_/ ___/__________(_)___  ____ _
  | |/ / _ \/ __/\__ \/ ___/ ___/ / __ \/ __ `/
  |___/\___/\__/____/(_  )/__/ /  / / / / /_/ /
                     /____/   /_/  /_/ /_/\__, /
                                          /____/
        Network Scanner & Reconnaissance Toolkit
              Authorized use only. Be loud on purpose.
"""


def print_banner() -> None:
    sys.stdout.write(cyan(BANNER))
    sys.stdout.write(dim("    " + "-" * 60 + "\n"))


# --- Time -------------------------------------------------------------------

def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp, e.g. 2026-07-17T12:34:56Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Target parsing ---------------------------------------------------------

def parse_targets(target: str) -> List[str]:
    """Parse a target spec into a list of IPs / CIDRs.

    Accepts:
        - Single IP        : 192.168.1.10
        - CIDR             : 192.168.1.0/24
        - Dash range       : 192.168.1.1-192.168.1.50
        - Comma-separated  : 192.168.1.1,192.168.1.5
    """
    if not target or not target.strip():
        raise ValueError("empty target")

    target = target.strip()
    out: List[str] = []

    # Comma-separated list of any of the above
    for part in target.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            # CIDR
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR '{part}': {exc}") from exc
            # /31, /32 are still valid but skip in CLI default; cap huge nets
            if net.num_addresses > 4096:
                raise ValueError(
                    f"CIDR {part} has {net.num_addresses} hosts; "
                    f"max 4096 to avoid runaway scans"
                )
            out.extend(str(h) for h in net.hosts())
        elif "-" in part and part.count(".") >= 3:
            # Range  a.b.c.d - e.f.g.h
            try:
                start_s, end_s = [x.strip() for x in part.split("-", 1)]
                start = ipaddress.ip_address(start_s)
                end = ipaddress.ip_address(end_s)
            except (ValueError, IndexError) as exc:
                raise ValueError(f"invalid range '{part}': {exc}") from exc
            if int(end) < int(start):
                raise ValueError(f"range end < start: {part}")
            if int(end) - int(start) > 4095:
                raise ValueError(
                    f"range {part} exceeds 4096 hosts; narrow it down"
                )
            cur = int(start)
            while cur <= int(end):
                out.append(str(ipaddress.ip_address(cur)))
                cur += 1
        else:
            # Single IP
            try:
                out.append(str(ipaddress.ip_address(part)))
            except ValueError as exc:
                raise ValueError(f"invalid IP '{part}': {exc}") from exc

    # Dedupe, preserve order
    seen = set()
    deduped: List[str] = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


# --- Port-range parsing -----------------------------------------------------

_PORT_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def parse_ports(spec: str) -> List[int]:
    """Parse a port spec into a sorted, deduped list of ints.

    Accepts:
        - "top100", "top1000"   -> preset lists
        - "1-1024"              -> range
        - "22,80,443"           -> list
        - "22,80,8000-8100"     -> mixed
    """
    spec = (spec or "").strip().lower()
    if not spec:
        return list(range(1, 1025))

    if spec in ("top100", "common", "common100"):
        return list(TOP_100_PORTS)
    if spec == "top1000":
        return list(TOP_1000_PORTS)
    if spec == "all":
        return list(range(1, 65536))

    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = _PORT_RANGE_RE.match(chunk)
        if not m:
            raise ValueError(f"invalid port spec '{chunk}'")
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        if not (0 <= a <= 65535) or not (0 <= b <= 65535):
            raise ValueError(f"port out of range in '{chunk}'")
        if b < a:
            raise ValueError(f"range end < start in '{chunk}'")
        out.update(range(a, b + 1))
    return sorted(out)


# --- Top-N port presets -----------------------------------------------------

# Top 100 TCP ports (IANA/common-services + nmap top reference)
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 37, 43, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84,
    85, 88, 89, 90, 99, 100, 101, 102, 104, 110, 111, 113, 119, 123, 125, 135,
    137, 138, 139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212, 222, 254,
    255, 259, 264, 280, 301, 306, 311, 340, 366, 389, 399, 425, 427, 443, 444,
    445, 458, 464, 465, 481, 487, 491, 500, 512, 513, 514, 515, 524, 541, 548,
    554, 555, 563, 587, 593, 631, 636, 873, 902, 989, 990, 993, 995, 1000,
]

# A pragmatic "top 1000" — included as a smaller curated list to keep
# the file self-contained. For exhaustive scanning, override via --ports.
TOP_1000_PORTS = sorted(set(
    TOP_100_PORTS +
    [
        # common web/alt-http/db
        81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 101, 102, 104, 110, 111, 113,
        119, 123, 125, 135, 137, 138, 139, 143, 144, 146, 161, 162, 163, 179,
        199, 211, 212, 222, 254, 255, 259, 264, 280, 301, 306, 311, 340, 366,
        389, 399, 425, 427, 443, 444, 445, 458, 464, 465, 481, 487, 491, 500,
        512, 513, 514, 515, 524, 541, 548, 554, 555, 563, 587, 593, 631, 636,
        873, 902, 989, 990, 993, 995, 1000,
        # additional common
        1080, 1099, 1234, 1433, 1434, 1521, 1701, 1723, 1741, 1812, 1900,
        2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375, 2376,
        3000, 3001, 3306, 3389, 4000, 4045, 4444, 5000, 5001, 5060, 5222,
        5432, 5601, 5900, 5984, 5985, 5986, 6379, 6660, 6661, 6667, 7077,
        7474, 8000, 8008, 8009, 8080, 8081, 8088, 8089, 8090, 8443, 8500,
        8888, 9000, 9001, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000,
        11211, 15672, 26379, 27017, 27018, 27019, 28017, 50070, 50000,
    ]
))


# --- Logging ----------------------------------------------------------------

class StderrLogger:
    """Minimal stderr logger that respects --quiet."""

    def __init__(self, quiet: bool = False, verbose: bool = False) -> None:
        self.quiet = quiet
        self.verbose = verbose

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(f"{dim('[i]')} {msg}", file=sys.stderr)

    def ok(self, msg: str) -> None:
        if not self.quiet:
            print(f"{green('[+]')} {msg}", file=sys.stderr)

    def warn(self, msg: str) -> None:
        print(f"{yellow('[!]')} {msg}", file=sys.stderr)

    def err(self, msg: str) -> None:
        print(f"{red('[-]')} {msg}", file=sys.stderr)

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(f"{dim('[d]')} {msg}", file=sys.stderr)


# --- Misc helpers -----------------------------------------------------------

def chunked(iterable: Iterable, size: int):
    """Yield successive `size`-sized chunks from an iterable."""
    chunk: list = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def is_root() -> bool:
    """True if running with effective UID 0 (POSIX). On Windows, returns False."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False

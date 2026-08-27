"""Shared utilities for NetScope.

The module intentionally has no third-party dependencies. It contains the
validation used by both the command line and NiceGUI interfaces so invalid
input is rejected before any network I/O starts.
"""
from __future__ import annotations

import ipaddress
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


class ValidationError(ValueError):
    """A user-facing validation failure."""


def _color_enabled() -> bool:
    return not os.environ.get("NO_COLOR") and sys.stdout.isatty()


_USE_COLOR = _color_enabled()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def red(t: str) -> str: return _c("31", t)
def green(t: str) -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def blue(t: str) -> str: return _c("34", t)
def magenta(t: str) -> str: return _c("35", t)
def cyan(t: str) -> str: return _c("36", t)
def bold(t: str) -> str: return _c("1", t)
def dim(t: str) -> str: return _c("2", t)


BANNER = r"""
 _   _ _____ _____ ____   ____ ___  ____  _____
| \ | | ____|_   _/ ___| / ___/ _ \|  _ \| ____|
|  \| |  _|   | | \___ \| |  | | | | |_) |  _|
| |\  | |___  | |  ___) | |__| |_| |  __/| |___
|_| \_|_____| |_| |____/ \____\___/|_|   |_____|

        Network Scanner & Reconnaissance Toolkit
              Authorized use only. Be loud on purpose.
"""


def print_banner() -> None:
    sys.stdout.write(cyan(BANNER))
    sys.stdout.write(dim("    " + "-" * 60 + "\n"))


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _duration_seconds(start_iso: str, end_iso: str) -> float:
    try:
        s = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        e = datetime.strptime(end_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return max(0.0, (e - s).total_seconds())
    except Exception:
        return 0.0


def validate_timeout(value: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("timeout must be a number") from exc
    if not math.isfinite(result) or result < 0.01 or result > 120:
        raise ValidationError("timeout must be finite and between 0.01 and 120 seconds")
    return result


def validate_workers(value: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("workers must be an integer") from exc
    if result < 1 or result > 1024:
        raise ValidationError("workers must be between 1 and 1024")
    return result


def validate_rate_limit(value: Optional[float]) -> Optional[float]:
    if value in (None, "", 0, 0.0):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("rate limit must be a number") from exc
    if not math.isfinite(result) or result <= 0 or result > 100000:
        raise ValidationError("rate limit must be finite and between 0 and 100000 probes/second")
    return result


def normalize_domain(value: str) -> str:
    raw = (value or "").strip()
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw:
        raise ValidationError("domain is required")
    if "://" in raw or "/" in raw or any(ch in raw for ch in " ,@[]"):
        raise ValidationError("domain must be a hostname, not a URL or address list")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValidationError("an IPv4 address is not a domain")
    labels = raw.split(".")
    if len(labels) < 2:
        raise ValidationError("domain must contain at least one dot")
    encoded: list[str] = []
    for label in labels:
        if not label:
            raise ValidationError("domain contains an empty label")
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValidationError("domain contains an invalid label") from exc
        if len(ascii_label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?[a-z0-9]?", ascii_label):
            raise ValidationError(f"invalid domain label: {label!r}")
        encoded.append(ascii_label)
    domain = ".".join(encoded)
    if len(domain) > 253:
        raise ValidationError("domain is longer than 253 characters")
    return domain


def is_domain(value: str) -> bool:
    try:
        normalize_domain(value)
        return True
    except ValidationError:
        return False


def parse_single_ipv4(value: str) -> str:
    raw = (value or "").strip()
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValidationError(f"invalid IPv4 address: {raw!r}") from exc
    if addr.version != 4:
        raise ValidationError("IPv6 scanning is not supported; provide an IPv4 target")
    return str(addr)


def validate_output_dir(value: Optional[str], *, create: bool = False) -> Optional[str]:
    if value in (None, ""):
        return None
    path = Path(str(value)).expanduser()
    if path.exists() and not path.is_dir():
        raise ValidationError(f"output path is not a directory: {path}")
    if create:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValidationError(f"cannot create output directory: {exc}") from exc
    return str(path)


def validate_wordlist(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise ValidationError(f"wordlist does not exist: {candidate}")
    if not os.access(candidate, os.R_OK):
        raise ValidationError(f"wordlist is not readable: {candidate}")
    return str(candidate)


def parse_targets(target: str) -> List[str]:
    """Parse IPv4 addresses, CIDRs, ranges, and comma-separated lists."""
    if not target or not target.strip():
        raise ValidationError("target is required")
    out: list[str] = []
    for part in target.strip().split(","):
        part = part.strip()
        if not part:
            raise ValidationError("target contains an empty list item")
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                if ":" in part:
                    raise ValidationError("IPv6 scanning is not supported; provide an IPv4 target") from exc
                raise ValidationError(f"invalid CIDR '{part}': {exc}") from exc
            if net.version != 4:
                raise ValidationError("IPv6 scanning is not supported; provide an IPv4 target")
            if net.num_addresses > 4096:
                raise ValidationError(f"CIDR {part} exceeds the 4096-host safety limit")
            out.extend(str(host) for host in net.hosts())
            continue
        if "-" in part:
            pieces = [piece.strip() for piece in part.split("-", 1)]
            try:
                start = ipaddress.ip_address(pieces[0])
                end = ipaddress.ip_address(pieces[1])
            except (ValueError, IndexError) as exc:
                raise ValidationError(f"invalid range '{part}'") from exc
            if start.version != 4 or end.version != 4:
                raise ValidationError("IPv6 scanning is not supported; provide an IPv4 target")
            if int(end) < int(start):
                raise ValidationError(f"range end is before start: {part}")
            if int(end) - int(start) > 4095:
                raise ValidationError(f"range '{part}' exceeds the 4096-host safety limit")
            out.extend(str(ipaddress.ip_address(number)) for number in range(int(start), int(end) + 1))
            continue
        try:
            addr = ipaddress.ip_address(part)
        except ValueError as exc:
            if ":" in part:
                raise ValidationError("IPv6 scanning is not supported; provide an IPv4 target") from exc
            raise ValidationError(f"invalid IP '{part}'") from exc
        if addr.version != 4:
            raise ValidationError("IPv6 scanning is not supported; provide an IPv4 target")
        out.append(str(addr))

    deduped: list[str] = []
    seen: set[str] = set()
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def classify_target(target: str) -> str:
    if is_domain(target):
        return "domain"
    parse_targets(target)
    if "/" in target or "-" in target or "," in target:
        return "network"
    return "ip"


_PORT_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")

# Exactly 100 curated, widely deployed TCP ports. ``top1000`` is deliberately
# documented as the deterministic first 1000 ports rather than an incomplete
# frequency ranking.
TOP_100_PORTS = sorted({
    7, 20, 21, 22, 23, 25, 26, 37, 43, 53, 67, 68, 69, 79, 80, 81, 82, 83,
    84, 85, 88, 89, 90, 99, 100, 101, 102, 104, 110, 111, 113, 119, 123, 125,
    135, 137, 138, 139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212,
    222, 254, 255, 259, 264, 280, 301, 306, 311, 340, 366, 389, 399, 425,
    427, 443, 444, 445, 458, 464, 465, 481, 487, 491, 500, 512, 513, 514,
    515, 524, 541, 548, 554, 555, 563, 587, 593, 631, 636, 873, 902, 989,
    990, 993, 995, 1000, 3306, 3389, 5432, 5900, 6379, 8080,
})
if len(TOP_100_PORTS) != 100:
    raise RuntimeError("TOP_100_PORTS must contain exactly 100 ports")
TOP_1000_PORTS = list(range(1, 1001))
PORT_PRESETS = {
    "top100": TOP_100_PORTS,
    "common": TOP_100_PORTS,
    "common100": TOP_100_PORTS,
    "top1000": TOP_1000_PORTS,
    "first1000": TOP_1000_PORTS,
}


def parse_ports(spec: str | Sequence[int]) -> List[int]:
    if isinstance(spec, (list, tuple, set)):
        values = list(spec)
    else:
        value = (spec or "").strip().lower()
        if not value:
            raise ValidationError("port specification is required")
        if value in PORT_PRESETS:
            return list(PORT_PRESETS[value])
        if value == "all":
            return list(range(1, 65536))
        values = []
        for chunk in value.split(","):
            if not chunk:
                raise ValidationError("port specification contains an empty item")
            match = _PORT_RANGE_RE.fullmatch(chunk.strip())
            if not match:
                raise ValidationError(f"invalid port spec '{chunk}'")
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValidationError(f"port out of range in '{chunk}'")
            if end < start:
                raise ValidationError(f"range end is before start in '{chunk}'")
            values.extend(range(start, end + 1))
    try:
        parsed = sorted({int(port) for port in values})
    except (TypeError, ValueError) as exc:
        raise ValidationError("ports must be integers") from exc
    if not parsed or any(port < 1 or port > 65535 for port in parsed):
        raise ValidationError("ports must be between 1 and 65535")
    return parsed


class StderrLogger:
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


def chunked(iterable: Iterable, size: int):
    if size < 1:
        raise ValueError("chunk size must be positive")
    chunk: list = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def is_root() -> bool:
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False

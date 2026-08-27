"""NetScope - multi-threaded TCP port scanner with banner grabbing.

- Concurrent.futures ThreadPoolExecutor (a worker per probe).
- Connect-only, no exploit payloads, no raw SYN scans: the tool stays
  compatible with the most cautious environments.
- Banner grabbing is opportunistic: open a fresh socket, send a small
  protocol probe if the service is well-known (HTTP, SMTP, FTP, SSH,
  POP3, IMAP, Redis, MySQL), and read until the first newline / banner
  end.  We never read more than BANNER_MAX bytes.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from . import __version__
from .utils import cyan, dim, green, red, yellow


# --- Result type ------------------------------------------------------------

@dataclass
class PortResult:
    host: str
    port: int
    open: bool = False
    state: str = "closed"  # "open" | "closed" | "filtered"
    banner: Optional[str] = None
    service_hint: Optional[str] = None
    rtt_ms: Optional[float] = None
    reason: str = ""
    http_info: Optional[dict] = None
    tls_info: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)


# --- Public entry point -----------------------------------------------------

def port_scan(
    host: str,
    ports: Sequence[int],
    *,
    timeout: float = 1.5,
    workers: int = 200,
    grab_banner: bool = True,
    logger=None,
    on_result: Optional[Callable[[PortResult], None]] = None,
    cancellation=None,
    rate_limit: Optional[float] = None,
) -> List[PortResult]:
    """Scan `host` over `ports` (an iterable of ints).

    Returns a list of PortResult, sorted by port, including both open and
    closed/filtered results (closed/filtered are reported at debug level
    only).
    """
    if logger is None:
        from .utils import StderrLogger
        logger = StderrLogger()

    from .utils import parse_ports, parse_single_ipv4, validate_rate_limit, validate_timeout, validate_workers
    host = parse_single_ipv4(host)
    timeout = validate_timeout(timeout)
    workers = validate_workers(workers)
    ports = parse_ports(ports)
    rate_limit = validate_rate_limit(rate_limit)
    if not ports:
        logger.warn("empty port list — nothing to scan")
        return []

    logger.info(
        f"port scan {host} — {len(ports)} port(s), workers={workers}, "
        f"timeout={timeout}s, banner={grab_banner}"
    )

    results: List[PortResult] = []
    limiter = _RateLimiter(rate_limit) if rate_limit else None
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {
        executor.submit(_probe, host, p, timeout, grab_banner, limiter, cancellation): p
        for p in ports
    }
    try:
        for fut in as_completed(futures):
            if _cancelled(cancellation):
                break
            p = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                res = PortResult(host=host, port=p, reason=f"exception: {exc}")
            results.append(res)
            if on_result:
                on_result(res)
            if res.open:
                extra = [yellow(res.service_hint)] if res.service_hint else []
                if res.banner:
                    bn = res.banner.replace("\r", " ").replace("\n", " ")
                    extra.append(dim(f'"{bn[:77] + "..." if len(bn) > 80 else bn}"'))
                logger.ok(f"  {host}:{p:<5d}  {green('open')}  " + "  ".join(extra))
            else:
                logger.debug(f"  {host}:{p}  {res.state} ({res.reason})")
    finally:
        if _cancelled(cancellation):
            for fut in futures:
                fut.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
        else:
            executor.shutdown(wait=True)

    results.sort(key=lambda r: r.port)
    n_open = sum(1 for r in results if r.open)
    logger.ok(f"{n_open} open / {len(results)} scanned on {host}")
    return results


# --- Single-port probe -----------------------------------------------------

def _probe(host: str, port: int, timeout: float, grab: bool, rate_limiter=None, cancellation=None) -> PortResult:
    t0 = time.perf_counter()
    res = PortResult(host=host, port=port)

    if _cancelled(cancellation):
        res.reason = "cancelled"
        return res
    if rate_limiter:
        rate_limiter.wait(cancellation)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((host, port))
        except socket.timeout:
            res.state = "filtered"
            res.reason = "connect-timeout"
            return res
        except ConnectionRefusedError:
            res.state = "closed"
            res.reason = "refused"
            return res
        except OSError as exc:
            res.state = "filtered"
            res.reason = f"os-error: {exc}"
            return res

        res.open = True
        res.state = "open"
        res.rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        res.service_hint = _service_hint(port)
        if _is_tls_port(port):
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=None if _is_ip(host) else host)
                res.tls_info = _tls_observation(s, host, port)
            except Exception as exc:
                res.tls_info = {"error": str(exc)}
        if grab:
            res.banner = _grab_banner(s, port, timeout)
            if _is_http_port(port):
                res.http_info = _http_observation(res.banner, "https" if _is_tls_port(port) else "http")
        return res
    finally:
        try:
            s.close()
        except Exception:
            pass


# --- Banner grabbing -------------------------------------------------------

BANNER_MAX = 256
BANNER_READ_TIMEOUT = 1.5


# Probes we send BEFORE reading — services that need a kick to talk.
# Order: service-guess, bytes.
_HTTP_PROBE = f"HEAD / HTTP/1.0\r\nUser-Agent: NetScope/{__version__}\r\n\r\n".encode("ascii")

_PROBES = [
    ("http",    _HTTP_PROBE),
    ("smtp",    b"EHLO netscope.local\r\n"),
    ("ftp",     b"USER anonymous\r\n"),
    ("pop3",    b"QUIT\r\n"),
    ("imap",    b"A1 LOGOUT\r\n"),
    ("redis",   b"PING\r\n"),
    ("mysql",   b""),
    ("ssh",     b""),
    ("default", b""),
]


def _probe_for(port: int) -> Tuple[str, bytes]:
    """Pick a probe based on the port's likely service."""
    hint = _service_hint(port)
    if hint in {"http", "http-alt"}:
        hint = "http"
    if hint in {"https", "https-alt"}:
        hint = "http"
    for name, _ in _PROBES:
        if name == hint:
            return name, dict(_PROBES)[name]
    return "default", b""


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> Optional[str]:
    """Send a protocol-appropriate probe and read the first line / banner."""
    name, probe = _probe_for(port)
    try:
        if probe:
            sock.sendall(probe)
        sock.settimeout(min(BANNER_READ_TIMEOUT, timeout))
        data = b""
        # Read until newline or BANNER_MAX or socket quiet.
        while len(data) < BANNER_MAX:
            try:
                chunk = sock.recv(BANNER_MAX - len(data))
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\n" in data or len(data) >= 64:
                # One line is usually enough for a banner.
                break
        if not data:
            return None
        text = data.decode("utf-8", errors="replace").strip()
        return text
    except Exception:
        return None


def _cancelled(token) -> bool:
    if token is None:
        return False
    method = getattr(token, "is_cancelled", None)
    return bool(method()) if callable(method) else bool(getattr(token, "cancelled", False))


class _RateLimiter:
    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / rate
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self, cancellation=None) -> None:
        with self._lock:
            now = time.monotonic()
            due = max(now, self._next)
            self._next = due + self.interval
        while due > time.monotonic():
            if _cancelled(cancellation):
                return
            time.sleep(min(0.02, due - time.monotonic()))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_tls_port(port: int) -> bool:
    return port in {443, 465, 636, 989, 990, 993, 995, 2376, 5986, 8443}


def _is_http_port(port: int) -> bool:
    return port in {80, 81, 88, 89, 3000, 3001, 4000, 443, 5000, 5001, 5601, 8000, 8008, 8080, 8081, 8088, 8089, 8090, 8443, 8888, 9000, 9001, 9999, 10000}


def _http_observation(banner: Optional[str], scheme: str) -> Optional[dict]:
    if not banner:
        return None
    match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", banner, re.IGNORECASE)
    if not match:
        return None
    result = {"scheme": scheme, "status": int(match.group(1))}
    for name, key in (("server", "server"), ("content-type", "content_type"), ("location", "location")):
        header = re.search(rf"^{re.escape(name)}:\s*(.+)$", banner, re.IGNORECASE | re.MULTILINE)
        if header:
            result[key] = header.group(1).strip()[:512]
    return result


def _tls_observation(sock: ssl.SSLSocket, host: str, port: int) -> dict:
    result: dict = {"protocol": sock.version(), "cipher": (sock.cipher() or [None])[0]}
    raw = sock.getpeercert(binary_form=True)
    if not raw:
        return result
    result["sha256_fingerprint"] = hashlib.sha256(raw).hexdigest().upper()
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(raw)
        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(name.value) for name in san_extension.value]
        except Exception:
            sans = []
        result.update({
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": getattr(cert, "not_valid_before_utc", cert.not_valid_before).isoformat(),
            "not_after": getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
            "serial_number": str(cert.serial_number),
            "sans": sans,
        })
    except Exception:
        pass
    return result


# --- Service hint (port -> name) -------------------------------------------

_COMMON_PORTS = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 26: "smtp", 37: "time", 43: "whois", 53: "dns",
    67: "dhcp", 68: "dhcp-client", 69: "tftp", 79: "finger",
    80: "http", 81: "http-alt", 88: "kerberos", 89: "http-alt",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmp-trap",
    179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "lpr",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    902: "vmware", 989: "ftps-data", 990: "ftps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1099: "rmi", 1194: "openvpn",
    1433: "mssql", 1434: "mssql", 1521: "oracle", 1701: "l2tp",
    1723: "pptp", 1812: "radius", 1900: "upnp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls",
    3000: "http-alt", 3001: "http-alt", 3306: "mysql",
    3389: "rdp", 4000: "http-alt", 4444: "metasploit", 5000: "http-alt",
    5001: "http-alt", 5060: "sip", 5222: "xmpp", 5432: "postgresql",
    5601: "kibana", 5900: "vnc", 5984: "couchdb", 5985: "winrm",
    5986: "winrm-ssl", 6379: "redis", 6660: "irc", 6667: "irc",
    7001: "weblogic", 7474: "neo4j", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp", 8080: "http-alt", 8081: "http-alt", 8088: "http-alt",
    8089: "http-alt", 8090: "http-alt", 8443: "https-alt", 8500: "http-alt",
    8888: "http-alt", 9000: "http-alt", 9001: "http-alt", 9042: "cassandra",
    9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9999: "http-alt", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 27019: "mongodb", 28017: "mongodb-web",
}


def _service_hint(port: int) -> str:
    return _COMMON_PORTS.get(port, "unknown")

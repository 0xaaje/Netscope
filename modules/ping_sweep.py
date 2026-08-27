"""IPv4 host discovery using ICMP, or ARP on a directly attached LAN."""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional

from .utils import ValidationError, cyan, dim, green, is_root, parse_targets


class PrivilegeUnavailable(RuntimeError):
    """Raised when a requested privileged discovery method cannot run safely."""


@dataclass
class Host:
    ip: str
    alive: bool = False
    rtt_ms: Optional[float] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    method: str = "none"  # arp | icmp | dns | manual
    reason: str = ""
    ttl: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


OUI_PREFIXES: Dict[str, str] = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "00:1A:11": "Google", "3C:5A:B4": "Google",
    "F4:F5:D8": "Google", "00:15:5D": "Hyper-V", "00:03:FF": "Microsoft", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "AC:DE:48": "Apple", "F0:18:98": "Apple",
    "3C:22:FB": "Apple", "00:1B:63": "Apple", "00:50:F2": "Microsoft", "D4:BE:D9": "Dell",
    "B0:83:FE": "Dell", "00:14:22": "Dell", "00:1E:C9": "Dell", "3C:D9:2B": "HP", "00:08:02": "HP",
    "00:23:7D": "HP", "00:1A:2B": "HP", "00:26:55": "HP", "00:26:F1": "Intel", "3C:A9:F4": "Intel",
    "A0:36:9F": "Intel", "70:38:EE": "Intel", "F8:63:3F": "Intel", "00:1E:67": "Intel", "00:1F:3C": "Intel",
    "00:26:C6": "Intel", "C8:FF:28": "Intel", "B4:B5:2F": "Intel", "F0:DE:F1": "Intel", "00:25:96": "Cisco",
    "00:1B:0D": "Cisco", "00:26:0A": "Cisco", "F8:4F:57": "Netgear", "20:4E:7F": "Netgear", "C4:3D:C7": "Netgear",
    "B0:7F:B9": "Netgear", "C0:25:06": "TP-Link", "50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link", "14:CC:20": "TP-Link",
    "30:B5:C2": "TP-Link", "00:1D:7E": "Linksys", "C0:56:27": "Belkin",
}


def vendor_from_mac(mac: str) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){2}[0-9A-F]{2}", prefix):
        return None
    return OUI_PREFIXES.get(prefix, "Unknown")


def _cancelled(token) -> bool:
    if token is None:
        return False
    method = getattr(token, "is_cancelled", None)
    return bool(method()) if callable(method) else bool(getattr(token, "cancelled", False))


def _directly_connected_ipv4(hosts: List[str]) -> bool:
    """Return true only when all hosts are on a local Linux link route."""
    if not hosts or sys.platform != "linux" or any(ipaddress.ip_address(ip).is_loopback for ip in hosts):
        return False
    ip_binary = shutil.which("ip")
    if not ip_binary:
        return False
    try:
        proc = subprocess.run(
            [ip_binary, "-4", "route", "show", "scope", "link"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    networks = []
    for line in proc.stdout.splitlines():
        token = line.split(None, 1)[0] if line.split() else ""
        if token == "default":
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return bool(networks) and all(any(ipaddress.ip_address(ip) in net for net in networks) for ip in hosts)


def arp_available(targets: List[str]) -> tuple[bool, str]:
    if any(ipaddress.ip_address(ip).version != 4 for ip in targets):
        return False, "ARP discovery supports IPv4 only"
    if not _scapy_available():
        return False, "Scapy is not installed"
    if not is_root():
        return False, "ARP discovery requires CAP_NET_RAW/root; use ICMP as the safe fallback"
    if not _directly_connected_ipv4(targets):
        return False, "targets are not all on a directly connected IPv4 link"
    return True, "ARP is available on the directly connected IPv4 link"


def ping_sweep(
    target: str,
    *,
    timeout: float = 1.0,
    workers: int = 128,
    method: str = "auto",
    logger=None,
    on_result: Optional[Callable[[Host], None]] = None,
    cancellation=None,
) -> List[Host]:
    from .utils import StderrLogger, validate_timeout, validate_workers
    logger = logger or StderrLogger()
    timeout = validate_timeout(timeout)
    workers = validate_workers(workers)
    if method not in {"auto", "arp", "icmp"}:
        raise ValidationError("discovery method must be auto, arp, or icmp")
    hosts = parse_targets(target)
    if not hosts:
        raise ValidationError("target produced no IPv4 hosts")
    logger.info(f"ping sweep on {len(hosts)} host(s) — workers={workers}, timeout={timeout}s")

    available, reason = arp_available(hosts)
    if method == "arp" and not available:
        raise PrivilegeUnavailable(f"ARP discovery unavailable: {reason}")
    chosen = "arp" if method == "arp" or (method == "auto" and available) else "icmp"
    if method == "auto" and not available:
        logger.debug(f"auto-selected ICMP: {reason}")
    results = (_arp_sweep if chosen == "arp" else _icmp_sweep)(
        hosts, timeout=timeout, workers=workers, logger=logger,
        on_result=on_result, cancellation=cancellation,
    )
    alive = sum(1 for host in results if host.alive)
    logger.ok(f"{alive}/{len(results)} host(s) alive")
    return results


def _scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


def _arp_probe(ip: str, timeout: float) -> Host:
    from scapy.all import ARP, Ether, srp  # type: ignore
    host = Host(ip=ip, method="arp")
    try:
        answers, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=False, retry=0)
    except Exception as exc:
        host.reason = f"arp-error: {exc}"
        return host
    if not answers:
        host.reason = "no-arp-reply"
        return host
    _, received = answers[0]
    host.alive = True
    host.mac = received.hwsrc.upper() if received.hwsrc else None
    host.vendor = vendor_from_mac(host.mac or "")
    return host


def _collect_probes(hosts: List[str], probe: Callable[[str, float], Host], *, timeout: float, workers: int, logger, on_result, cancellation, method: str) -> List[Host]:
    results: List[Host] = []
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {executor.submit(probe, ip, timeout): ip for ip in hosts}
    try:
        for future in as_completed(futures):
            ip = futures[future]
            if _cancelled(cancellation):
                break
            try:
                host = future.result()
            except Exception as exc:
                host = Host(ip=ip, method=method, reason=f"exception: {exc}")
            results.append(host)
            if on_result:
                on_result(host)
            if host.alive:
                if method == "arp":
                    logger.ok(f"  {cyan(host.ip):>15s}  {dim('mac=' + (host.mac or '?'))}")
                else:
                    rtt = f"{host.rtt_ms:.1f}ms" if host.rtt_ms is not None else "?ms"
                    logger.ok(f"  {cyan(host.ip):>15s}  {dim('rtt=' + rtt)}")
    finally:
        if _cancelled(cancellation):
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
        else:
            executor.shutdown(wait=True)
    results.sort(key=lambda host: int(ipaddress.ip_address(host.ip)))
    return results


def _arp_sweep(hosts: List[str], *, timeout: float, workers: int, logger, on_result=None, cancellation=None) -> List[Host]:
    logger.info("using ARP sweep (Scapy, directly connected IPv4 link)")
    return _collect_probes(hosts, _arp_probe, timeout=timeout, workers=workers, logger=logger, on_result=on_result, cancellation=cancellation, method="arp")


_PING_RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
_PING_TTL_RE = re.compile(r"\bttl[=\s](\d+)", re.IGNORECASE)


def _ping_cmd(ip: str) -> List[str]:
    if not shutil.which("ping"):
        return ["ping", "-n", "1", ip]
    return ["ping", "-n", "1", ip] if sys.platform.startswith("win") else ["ping", "-c", "1", "-n", ip]


def _icmp_probe(ip: str, timeout: float) -> Host:
    host = Host(ip=ip, method="icmp")
    try:
        proc = subprocess.run(_ping_cmd(ip), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout + 0.5, text=True)
    except subprocess.TimeoutExpired:
        host.reason = "icmp-timeout"
        return host
    except FileNotFoundError:
        host.reason = "ping-binary-missing"
        return host
    except Exception as exc:
        host.reason = f"icmp-error: {exc}"
        return host
    output = proc.stdout or ""
    if proc.returncode == 0:
        host.alive = True
        if match := _PING_RTT_RE.search(output):
            host.rtt_ms = float(match.group(1))
        if match := _PING_TTL_RE.search(output):
            host.ttl = int(match.group(1))
    else:
        host.reason = "icmp-no-reply"
    return host


def _icmp_sweep(hosts: List[str], *, timeout: float, workers: int, logger, on_result=None, cancellation=None) -> List[Host]:
    logger.info("using ICMP sweep (subprocess ping, no root needed)")
    return _collect_probes(hosts, _icmp_probe, timeout=timeout, workers=workers, logger=logger, on_result=on_result, cancellation=cancellation, method="icmp")


def reverse_dns(hosts: List[Host], *, timeout: float = 1.0, workers: int = 64) -> None:
    from .utils import validate_timeout, validate_workers
    timeout = validate_timeout(timeout)
    workers = validate_workers(workers)
    targets = [host for host in hosts if host.alive and not host.hostname]
    if not targets:
        return
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_rdns, host.ip): host for host in targets}
        for future in as_completed(futures):
            try:
                name = future.result()
            except Exception:
                name = None
            if name:
                futures[future].hostname = name


def _rdns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

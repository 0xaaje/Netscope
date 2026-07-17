"""NetScope - ICMP / ARP ping sweep.

Two strategies, auto-selected:
  - ARP sweep (via scapy, requires root): preferred on a /24 LAN. ARP does
    not depend on the target's IP stack state, so it catches hosts that
    block ICMP.  Returns MAC + vendor hint as a bonus.
  - ICMP echo (subprocess ping): fall back when scapy is missing or we're
    not on a /24 LAN.  Slower and less reliable, but stdlib-only.

Both strategies are multi-threaded via concurrent.futures.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from .utils import cyan, dim, green, is_root, parse_targets, red, yellow


# --- Result type ------------------------------------------------------------

@dataclass
class Host:
    ip: str
    alive: bool = False
    rtt_ms: Optional[float] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    method: str = "none"  # "arp" | "icmp"
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- Tiny OUI vendor hint (first 24 bits -> short name) --------------------

# Keep this small and self-contained. Real-world vendors use a 30k-line
# IEEE file; for a recon tool, a short snapshot of the most common OUI
# prefixes is enough to make the report readable.  Misses fall back to
# "Unknown" in the report.
OUI_PREFIXES: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "00:15:5D": "Hyper-V",
    "00:03:FF": "Microsoft",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "3C:22:FB": "Apple",
    "00:1B:63": "Apple",
    "00:50:F2": "Microsoft",
    "D4:BE:D9": "Dell",
    "B0:83:FE": "Dell",
    "00:14:22": "Dell",
    "00:1E:C9": "Dell",
    "3C:D9:2B": "HP",
    "00:08:02": "HP",
    "00:23:7D": "HP",
    "00:1A:2B": "HP",
    "00:26:55": "HP",
    "00:26:F1": "Intel",
    "3C:A9:F4": "Intel",
    "A0:36:9F": "Intel",
    "70:38:EE": "Intel",
    "F8:63:3F": "Intel",
    "00:1E:67": "Intel",
    "00:1F:3C": "Intel",
    "00:26:C6": "Intel",
    "C8:FF:28": "Intel",
    "B4:B5:2F": "Intel",
    "F0:DE:F1": "Intel",
    "00:25:96": "Cisco",
    "00:1B:0D": "Cisco",
    "00:26:0A": "Cisco",
    "F8:4F:57": "Netgear",
    "20:4E:7F": "Netgear",
    "C4:3D:C7": "Netgear",
    "B0:7F:B9": "Netgear",
    "C0:25:06": "TP-Link",
    "50:C7:BF": "TP-Link",
    "EC:08:6B": "TP-Link",
    "14:CC:20": "TP-Link",
    "30:B5:C2": "TP-Link",
    "00:1D:7E": "Linksys",
    "C0:56:27": "Belkin",
}


def vendor_from_mac(mac: str) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    if not re.match(r"([0-9A-F]{2}:){3}", prefix):
        return None
    return OUI_PREFIXES.get(prefix, "Unknown")


# --- Public entry point -----------------------------------------------------

def ping_sweep(
    target: str,
    *,
    timeout: float = 1.0,
    workers: int = 128,
    method: str = "auto",   # "auto" | "arp" | "icmp"
    logger=None,
) -> List[Host]:
    """Return a list of Host records, one per probed IP.

    `target` is parsed by utils.parse_targets (CIDR / range / single).
    """
    if logger is None:
        from .utils import StderrLogger
        logger = StderrLogger()

    try:
        hosts = parse_targets(target)
    except ValueError as exc:
        logger.err(f"target parse failed: {exc}")
        return []

    if not hosts:
        logger.warn("no hosts resolved from target spec")
        return []

    logger.info(f"ping sweep on {len(hosts)} host(s) — workers={workers}, timeout={timeout}s")

    chosen = method
    if chosen == "auto":
        if _scapy_available() and is_root():
            chosen = "arp"
        else:
            chosen = "icmp"
        logger.debug(f"auto-selected method: {chosen}")

    if chosen == "arp":
        results = _arp_sweep(hosts, timeout=timeout, workers=workers, logger=logger)
    else:
        results = _icmp_sweep(hosts, timeout=timeout, workers=workers, logger=logger)

    alive = [h for h in results if h.alive]
    logger.ok(f"{len(alive)}/{len(results)} host(s) alive")
    return results


# --- ARP sweep via scapy ---------------------------------------------------

def _scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


def _arp_probe(ip: str, timeout: float) -> Host:
    """Send a single ARP who-has, return Host."""
    from scapy.all import ARP, Ether, srp  # type: ignore

    h = Host(ip=ip, method="arp")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    try:
        ans, _ = srp(pkt, timeout=timeout, verbose=False, retry=0)
    except Exception as exc:  # permission, no iface, etc.
        h.reason = f"arp-error: {exc}"
        return h
    if not ans:
        h.reason = "no-arp-reply"
        return h
    snd, rcv = ans[0]
    h.alive = True
    h.mac = rcv.hwsrc.upper() if rcv.hwsrc else None
    h.vendor = vendor_from_mac(h.mac or "")
    return h


def _arp_sweep(
    hosts: List[str], *, timeout: float, workers: int, logger
) -> List[Host]:
    logger.info("using ARP sweep (scapy, requires root)")
    out: List[Host] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_arp_probe, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                h = fut.result()
            except Exception as exc:
                h = Host(ip=ip, method="arp", reason=f"exception: {exc}")
            if h.alive:
                tag = cyan(f"  {h.ip:>15s}")
                extra = []
                if h.mac:
                    extra.append(dim(f"mac={h.mac}"))
                if h.vendor and h.vendor != "Unknown":
                    extra.append(yellow(h.vendor))
                elif h.vendor == "Unknown":
                    extra.append(dim("vendor=Unknown"))
                logger.ok(f"{tag}  " + "  ".join(extra))
            out.append(h)
    out.sort(key=lambda x: [int(p) for p in x.ip.split(".")])
    return out


# --- ICMP sweep via subprocess ping ---------------------------------------

# Per-platform default ping invocation. We do NOT pass -w/-W for short
# timeouts because flag semantics differ; the subprocess timeout covers it.
def _ping_cmd(ip: str) -> List[str]:
    if shutil.which("ping"):
        # Linux/macOS: -c 1 (count), -W is in seconds on Linux, ms on macOS
        # so we let the subprocess timeout enforce the bound.
        return ["ping", "-c", "1", "-n", ip]
    # Windows fallback (Git Bash / WSL usually have ping anyway)
    return ["ping", "-n", "1", ip]


_PING_RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def _icmp_probe(ip: str, timeout: float) -> Host:
    h = Host(ip=ip, method="icmp")
    try:
        proc = subprocess.run(
            _ping_cmd(ip),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5,
            text=True,
        )
    except subprocess.TimeoutExpired:
        h.reason = "icmp-timeout"
        return h
    except FileNotFoundError:
        h.reason = "ping-binary-missing"
        return h
    except Exception as exc:
        h.reason = f"icmp-error: {exc}"
        return h

    out = (proc.stdout or "")
    if proc.returncode == 0 and ("ttl=" in out.lower() or "bytes from" in out.lower()):
        m = _PING_RTT_RE.search(out)
        h.alive = True
        if m:
            try:
                h.rtt_ms = float(m.group(1))
            except ValueError:
                pass
    else:
        h.reason = "icmp-no-reply"
    return h


def _icmp_sweep(
    hosts: List[str], *, timeout: float, workers: int, logger
) -> List[Host]:
    logger.info("using ICMP sweep (subprocess ping, no root needed)")
    out: List[Host] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_icmp_probe, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                h = fut.result()
            except Exception as exc:
                h = Host(ip=ip, method="icmp", reason=f"exception: {exc}")
            if h.alive:
                rtt = f"{h.rtt_ms:.1f}ms" if h.rtt_ms is not None else "?ms"
                ip_padded = f"{h.ip:>15s}"
                logger.ok(f"  {cyan(ip_padded)}  {dim('rtt=' + rtt)}")
            out.append(h)
    out.sort(key=lambda x: [int(p) for p in x.ip.split(".")])
    return out


# --- Reverse DNS (cheap, optional follow-up) ------------------------------

def reverse_dns(hosts: List[Host], *, timeout: float = 1.0, workers: int = 64) -> None:
    """Fill .hostname on each alive Host in-place."""
    targets = [h for h in hosts if h.alive and not h.hostname]
    if not targets:
        return
    socket.setdefaulttimeout(timeout)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_rdns, h.ip): h for h in targets}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                name = fut.result()
            except Exception:
                name = None
            if name:
                h.hostname = name
    socket.setdefaulttimeout(None)


def _rdns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

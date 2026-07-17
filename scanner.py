#!/usr/bin/env python3
"""NetScope - Network Scanner & Reconnaissance Toolkit.

A modular, multi-threaded scanner for authorized testing on networks you
own or have written permission to assess.  Designed to run on Kali Linux
with stdlib only; the optional deps (scapy, requests) unlock extra
features (ARP sweep, crt.sh passive subdomain enum).

Modules:
    ping_sweep        ICMP / ARP host discovery
    port_scanner      multi-threaded TCP connect + banner grab
    service_detect    OS & service version guesses from banners
    subdomain_enum    crt.sh + wordlist subdomain enumeration
    exporter          JSON + human-readable text reports
    utils             shared helpers (color, parsing, port presets)

Usage examples (see README.md for the full guide):
    # Discover hosts on a /24
    sudo python3 scanner.py ping 192.168.1.0/24

    # Port-scan + service detection on the live hosts
    sudo python3 scanner.py scan 192.168.1.0/24 --ports top1000

    # Subdomain enumeration
    python3 scanner.py subdomains example.com

    # Full sweep of one target
    sudo python3 scanner.py all 192.168.1.10 --ports 1-65535 -o output/

Safety: NO exploit payloads.  Connect-only TCP, banner-only fingerprints.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import traceback
from typing import Dict, List

# Make `python3 scanner.py` work without requiring the user to install the
# package.  Anything we import from .modules can also be reached by adding
# the script's directory to sys.path.
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from modules import utils as U                 # noqa: E402
from modules.ping_sweep import ping_sweep, reverse_dns   # noqa: E402
from modules.port_scanner import port_scan               # noqa: E402
from modules.service_detect import detect_services, detect_os  # noqa: E402
from modules.subdomain_enum import enumerate_subdomains, ensure_default_wordlist  # noqa: E402
from modules.exporter import build_report, write_json, write_text  # noqa: E402


# --- Subcommand implementations -------------------------------------------

def cmd_ping(args, logger):
    started = U.utcnow_iso()
    hosts = ping_sweep(
        args.target,
        timeout=args.timeout,
        workers=args.workers,
        method=args.ping_method,
        logger=logger,
    )
    if args.rdns:
        reverse_dns(hosts, timeout=1.0)
        for h in hosts:
            if h.hostname:
                logger.ok(f"  {h.ip:<15s}  {U.dim('hostname=' + h.hostname)}")
    finished = U.utcnow_iso()

    if args.output:
        out_dir = args.output
        os.makedirs(out_dir, exist_ok=True)
        report = build_report(
            target=args.target, hosts=hosts,
            port_results={}, service_guesses={}, os_guesses={},
            subdomains=None,
            started_at=started, finished_at=finished,
            scan_meta={"phase": "ping-sweep",
                       "ping_method": args.ping_method,
                       "rdns": bool(args.rdns)},
        )
        _write_outputs(report, out_dir, args.format)
    return 0


def cmd_port(args, logger):
    """Scan a single host (one IP, no discovery)."""
    started = U.utcnow_iso()
    ports = U.parse_ports(args.ports)
    results = port_scan(
        args.target,
        ports,
        timeout=args.timeout,
        workers=args.workers,
        grab_banner=not args.no_banner,
        logger=logger,
    )
    svcs = detect_services(results, ttl_observed=None)
    osg = detect_os(results, ttl_observed=None)

    # Synthesize a single-host hosts list so the report is uniform.
    from modules.ping_sweep import Host
    h = Host(ip=args.target, alive=True, method="manual")
    finished = U.utcnow_iso()
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        report = build_report(
            target=args.target, hosts=[h],
            port_results={args.target: results},
            service_guesses={args.target: svcs},
            os_guesses={args.target: osg},
            subdomains=None,
            started_at=started, finished_at=finished,
            scan_meta={"phase": "port-scan",
                       "ports": args.ports,
                       "banner": not args.no_banner,
                       "workers": args.workers,
                       "timeout": args.timeout},
        )
        _write_outputs(report, args.output, args.format)
    return 0


def cmd_scan(args, logger):
    """Discover + port-scan + service detect on a target range."""
    started = U.utcnow_iso()

    # 1) Discovery
    hosts = ping_sweep(
        args.target, timeout=args.timeout, workers=args.workers,
        method=args.ping_method, logger=logger,
    )
    if args.rdns:
        reverse_dns(hosts, timeout=1.0)
    alive = [h for h in hosts if h.alive]
    if not alive:
        logger.warn("no alive hosts — nothing to scan")
        return 1

    # 2) Port scan per alive host
    ports = U.parse_ports(args.ports)
    port_results: Dict[str, list] = {}
    service_guesses: Dict[str, list] = {}
    os_guesses: Dict[str, object] = {}

    for h in alive:
        logger.info(f"--- scanning {h.ip} ({h.hostname or 'no-rdns'}) ---")
        results = port_scan(
            h.ip, ports, timeout=args.timeout,
            workers=args.workers, grab_banner=not args.no_banner, logger=logger,
        )
        port_results[h.ip] = results
        service_guesses[h.ip] = detect_services(results)
        os_guesses[h.ip] = detect_os(results)

    finished = U.utcnow_iso()
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        report = build_report(
            target=args.target, hosts=hosts,
            port_results=port_results,
            service_guesses=service_guesses,
            os_guesses=os_guesses,
            subdomains=None,
            started_at=started, finished_at=finished,
            scan_meta={"phase": "scan",
                       "ping_method": args.ping_method,
                       "ports": args.ports,
                       "banner": not args.no_banner,
                       "workers": args.workers,
                       "timeout": args.timeout,
                       "rdns": bool(args.rdns)},
        )
        _write_outputs(report, args.output, args.format)
    return 0


def cmd_subdomains(args, logger):
    started = U.utcnow_iso()
    ensure_default_wordlist()
    subs = enumerate_subdomains(
        args.domain,
        method=args.method,
        wordlist=args.wordlist,
        workers=args.workers,
        timeout=args.timeout,
        logger=logger,
    )
    finished = U.utcnow_iso()
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        report = build_report(
            target=args.domain, hosts=[],
            port_results={}, service_guesses={}, os_guesses={},
            subdomains=subs,
            started_at=started, finished_at=finished,
            scan_meta={"phase": "subdomain-enum",
                       "method": args.method,
                       "wordlist": args.wordlist or "builtin"},
        )
        _write_outputs(report, args.output, args.format)
    return 0


def cmd_all(args, logger):
    """Network scan + subdomain enum in one shot.  Subdomains only when
    the target parses as a domain name (no slash, no IP-shaped)."""
    started = U.utcnow_iso()
    rc = cmd_scan(args, logger)
    if rc != 0:
        return rc
    if _looks_like_domain(args.target):
        logger.info("--- subdomain pass on the same target ---")
        subs = enumerate_subdomains(
            args.target, method="both", wordlist=args.wordlist,
            workers=args.workers, timeout=args.timeout, logger=logger,
        )
        # Append to whatever scan wrote
        if args.output:
            json_path = os.path.join(args.output, "report.json")
            if os.path.exists(json_path):
                import json as _json
                with open(json_path, "r", encoding="utf-8") as f:
                    report = _json.load(f)
                report["subdomains"] = [s.to_dict() for s in subs]
                report["meta"]["scan"]["subdomain_method"] = "both"
                finished = U.utcnow_iso()
                report["meta"]["finished_at"] = finished
                report["meta"]["duration_s"] = U._duration_seconds(
                    report["meta"]["started_at"], finished,
                )
                write_json(report, json_path)
                write_text(report, os.path.join(args.output, "report.txt"))
                logger.ok(f"updated: {json_path}")
    return 0


def _looks_like_domain(target: str) -> bool:
    import re
    t = target.strip().lower()
    if "/" in t or "," in t or "-" in t and t.count(".") == 1:
        # CIDR / range / list — skip
        return False
    # crude: has letters and at least one dot, no digits-only octets
    return bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", t)) and not t.replace(".", "").isdigit()


# --- Shared arg parser & helpers ------------------------------------------

def _write_outputs(report, out_dir: str, fmt: str) -> None:
    """Write the report in the requested format(s).  Always writes JSON
    (so downstream tools can consume it) plus the formats the user asked
    for."""
    json_path = os.path.join(out_dir, "report.json")
    write_json(report, json_path)
    logger = _global_logger  # set in main()
    logger.ok(f"wrote {json_path}")
    if fmt in ("text", "both"):
        txt_path = os.path.join(out_dir, "report.txt")
        write_text(report, txt_path)
        logger.ok(f"wrote {txt_path}")


# Module-level so _write_outputs can find it without threading args.
_global_logger = None  # type: ignore[var-annotated]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope - Network Scanner & Reconnaissance Toolkit "
                    "(authorized testing only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress info-level stderr messages")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="enable debug-level messages")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI color output")

    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    # common knobs (added to every subcommand)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-t", "--timeout", type=float, default=1.5,
                        help="per-probe timeout in seconds")
    common.add_argument("-w", "--workers", type=int, default=200,
                        help="max concurrent workers")
    common.add_argument("-o", "--output", metavar="DIR",
                        help="write JSON+text reports into DIR")
    common.add_argument("-f", "--format", choices=("json", "text", "both"),
                        default="both",
                        help="output format(s) to write when -o is set")

    # ping
    pp = sub.add_parser("ping", parents=[common],
                        help="discover live hosts (ICMP or ARP)",
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    pp.add_argument("target", help="IP, CIDR (e.g. 192.168.1.0/24) or range")
    pp.add_argument("--method", dest="ping_method",
                    choices=("auto", "arp", "icmp"), default="auto",
                    help="ping method (arp needs scapy + root)")
    pp.add_argument("--no-rdns", dest="rdns", action="store_false",
                    help="skip reverse-DNS lookups on alive hosts")
    pp.set_defaults(func=cmd_ping)

    # port (single host)
    pt = sub.add_parser("port", parents=[common],
                        help="TCP port-scan a single host",
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    pt.add_argument("target", help="single IP to scan")
    pt.add_argument("-p", "--ports", default="top1000",
                    help="port spec: top100, top1000, all, 1-1024, 22,80,443")
    pt.add_argument("--no-banner", action="store_true",
                    help="skip banner grabbing (faster)")
    pt.set_defaults(func=cmd_port)

    # scan (discover + port)
    ps = sub.add_parser("scan", parents=[common],
                        help="discover + TCP port-scan + service detection",
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ps.add_argument("target", help="IP, CIDR or range")
    ps.add_argument("-p", "--ports", default="top1000",
                    help="port spec: top100, top1000, all, 1-1024, 22,80,443")
    ps.add_argument("--method", dest="ping_method",
                    choices=("auto", "arp", "icmp"), default="auto")
    ps.add_argument("--no-rdns", dest="rdns", action="store_false")
    ps.add_argument("--no-banner", action="store_true",
                    help="skip banner grabbing (faster)")
    ps.set_defaults(func=cmd_scan)

    # subdomains
    psub = sub.add_parser("subdomains", parents=[common],
                          help="enumerate subdomains for a domain",
                          formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    psub.add_argument("domain", help="e.g. example.com")
    psub.add_argument("--method", choices=("passive", "active", "both"),
                      default="both",
                      help="passive=crt.sh only, active=wordlist only, both=combined")
    psub.add_argument("--wordlist", metavar="PATH",
                      help="path to subdomain wordlist (default: bundled)")
    psub.set_defaults(func=cmd_subdomains)

    # all
    pa = sub.add_parser("all", parents=[common],
                        help="scan + (if target is a domain) subdomains",
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    pa.add_argument("target", help="IP/CIDR/range, OR a domain like example.com")
    pa.add_argument("-p", "--ports", default="top1000",
                    help="port spec: top100, top1000, all, 1-1024, 22,80,443")
    pa.add_argument("--method", dest="ping_method",
                    choices=("auto", "arp", "icmp"), default="auto")
    pa.add_argument("--no-rdns", dest="rdns", action="store_false")
    pa.add_argument("--no-banner", action="store_true",
                    help="skip banner grabbing (faster)")
    pa.add_argument("--wordlist", metavar="PATH",
                    help="path to subdomain wordlist (default: bundled)")
    pa.set_defaults(func=cmd_all)

    return p


def install_signal_handlers(logger) -> None:
    """Make Ctrl+C a clean exit instead of a stack trace."""
    def _sigint(_signum, _frame):
        logger.warn("interrupted — exiting cleanly")
        sys.exit(130)
    signal.signal(signal.SIGINT, _sigint)


def main(argv: List[str] | None = None) -> int:
    global _global_logger
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        os.environ["NO_COLOR"] = "1"
        U._USE_COLOR = False  # type: ignore[attr-defined]

    logger = U.StderrLogger(quiet=args.quiet, verbose=args.verbose)
    _global_logger = logger

    U.print_banner()
    install_signal_handlers(logger)

    if U.is_root():
        logger.info(U.dim("running as root — ARP sweep and raw sockets enabled"))
    else:
        logger.info(U.dim("not running as root — using ICMP sweep and TCP connect"))

    if not _safety_ack(args, logger):
        return 2

    try:
        return args.func(args, logger)
    except KeyboardInterrupt:
        logger.warn("interrupted — exiting cleanly")
        return 130
    except Exception as exc:  # last-resort: never crash silently
        logger.err(f"fatal: {exc}")
        if args.verbose:
            traceback.print_exc()
        return 1


# --- Safety prompt ----------------------------------------------------------

# Many recon tools blow up the moment you run them because users fire at
# arbitrary internet hosts.  A single one-time prompt is the lightest
# friction that still makes the user think.  Disable with --yes.

def _safety_ack(args, logger) -> bool:
    if os.environ.get("NETSCOPE_I_KNOW_WHAT_IM_DOING") == "1":
        return True
    # Skip the prompt for obviously harmless operations (no target = no scan)
    if getattr(args, "cmd", None) in (None,):
        return True

    target = getattr(args, "target", None) or getattr(args, "domain", "") or ""
    logger.warn(
        "NetScope is a reconnaissance tool. Only run it against systems "
        "you own or have written permission to test."
    )
    logger.info(f"Target: {target}")
    if not sys.stdin.isatty():
        # Non-interactive: require the env opt-in
        logger.err("non-interactive run — set NETSCOPE_I_KNOW_WHAT_IM_DOING=1 to proceed")
        return False
    try:
        ans = input("Type 'yes' to continue, anything else to abort: ").strip().lower()
    except EOFError:
        return False
    if ans == "yes":
        return True
    logger.err("aborted by user")
    return False


if __name__ == "__main__":
    sys.exit(main())

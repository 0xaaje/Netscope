#!/usr/bin/env python3
"""NetScope command-line adapter.

The scanner engine lives in :mod:`modules.engine` so the CLI and NiceGUI use
the same validation, events, cancellation, and report generation paths.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import traceback
from typing import List

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from modules import __version__  # noqa: E402
from modules.engine import CancellationToken, ScanEngine, ScanEvent, ScanRequest  # noqa: E402
from modules.utils import ValidationError, parse_ports  # noqa: E402
from modules import utils as U  # noqa: E402


_active_token: CancellationToken | None = None


def _event_logger(event: ScanEvent, logger) -> None:
    if event.type == "port_opened":
        logger.ok(event.message)
    elif event.type == "host_discovered":
        logger.ok(event.message)
    elif event.type == "finding_created":
        logger.warn(event.message)
    elif event.type in {"scan_failed", "scan_cancelled"}:
        logger.warn(event.message)
    elif event.message and event.type in {"phase_started", "progress_updated"}:
        logger.info(event.message)


def _run(args, logger, operation: str) -> int:
    request = _request_from_args(args, operation)
    token = CancellationToken()
    global _active_token
    _active_token = token
    install_signal_handlers(logger, token)
    engine = ScanEngine(logger=logger)
    result = engine.run(request, event_sink=lambda event: _event_logger(event, logger), cancellation=token)
    _active_token = None
    if result.status == "cancelled":
        return 130
    return 0 if result.status == "completed" else 1


def cmd_ping(args, logger):
    return _run(args, logger, "ping")


def cmd_port(args, logger):
    return _run(args, logger, "port")


def cmd_scan(args, logger):
    return _run(args, logger, "scan")


def cmd_all(args, logger):
    return _run(args, logger, "all")


def cmd_subdomains(args, logger):
    return _run(args, logger, "subdomains")


def cmd_ui(args, logger):
    try:
        from ui import main as ui_main
    except ImportError as exc:
        logger.err(f"NiceGUI is not installed; install requirements.txt first ({exc})")
        return 1
    return ui_main(host=args.host, port=args.port)


def _request_from_args(args, operation: str) -> ScanRequest:
    profile = getattr(args, "profile", "standard")
    ports = getattr(args, "ports", "top1000")
    if profile == "custom":
        ports = parse_ports(ports)
    target = getattr(args, "domain", "") if operation == "subdomains" else getattr(args, "target", "")
    return ScanRequest(
        target=target, profile=profile,
        discovery_method=getattr(args, "ping_method", "auto"), ports=ports,
        timeout=args.timeout, workers=args.workers,
        reverse_dns=args.rdns, banner_inspection=not getattr(args, "no_banner", False),
        subdomain_enumeration=False, output_formats=args.format,
        output_directory=args.output, rate_limit=args.rate_limit,
        wordlist=getattr(args, "wordlist", None), operation=operation,
        subdomain_method=getattr(args, "method", "both") if operation == "subdomains" else "both",
    )


def _bounded_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not (value >= 0.01 and value <= 120):
        raise argparse.ArgumentTypeError("must be between 0.01 and 120")
    return value


def _bounded_workers(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= value <= 1024:
        raise argparse.ArgumentTypeError("must be between 1 and 1024")
    return value


def _rate_limit(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not (value > 0 and value <= 100000):
        raise argparse.ArgumentTypeError("must be between 0 and 100000")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netscope", description="NetScope — authorized IPv4 reconnaissance only.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress info-level stderr messages")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug-level messages")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    parser.add_argument("--yes", action="store_true", help="skip the authorization prompt (use only in controlled automation)")
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-t", "--timeout", type=_bounded_float, default=1.5, help="per-probe timeout in seconds")
    common.add_argument("-w", "--workers", type=_bounded_workers, default=200, help="maximum concurrent workers")
    common.add_argument("-o", "--output", metavar="DIR", help="directory for the requested report format(s)")
    common.add_argument("-f", "--format", choices=("json", "text", "both", "html", "all"), default="both", help="report format(s); json/text/both are exact")
    common.add_argument("--rate-limit", type=_rate_limit, help="maximum probes per second (unset means unlimited)")

    def add_rdns(command):
        group = command.add_mutually_exclusive_group()
        group.add_argument("--rdns", dest="rdns", action="store_true", help="perform reverse-DNS lookups")
        group.add_argument("--no-rdns", dest="rdns", action="store_false", help="skip reverse-DNS lookups")
        command.set_defaults(rdns=True)

    ping = sub.add_parser("ping", parents=[common], help="discover live IPv4 hosts")
    ping.add_argument("target", help="IPv4, CIDR, range, or comma-separated IPv4 list")
    ping.add_argument("--method", dest="ping_method", choices=("auto", "arp", "icmp"), default="auto", help="auto uses ARP only on a directly connected IPv4 link")
    add_rdns(ping)
    ping.set_defaults(func=cmd_ping)

    port = sub.add_parser("port", parents=[common], help="scan one IPv4 host")
    port.add_argument("target", help="one IPv4 address or resolvable domain")
    port.add_argument("-p", "--ports", default="top1000", help="top100, top1000 (ports 1-1000), all, range, or list")
    port.add_argument("--profile", choices=("quick", "standard", "full", "custom"), default="custom")
    port.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    port.set_defaults(rdns=False, func=cmd_port)

    scan = sub.add_parser("scan", parents=[common], help="discover and TCP-scan IPv4 targets")
    scan.add_argument("target", help="IPv4, CIDR, range, or resolvable domain")
    scan.add_argument("-p", "--ports", default="top1000", help="top100, top1000 (ports 1-1000), all, range, or list")
    # ``custom`` keeps an explicitly supplied ``--ports`` value authoritative;
    # named profiles still work when the operator selects one explicitly.
    scan.add_argument("--profile", choices=("quick", "standard", "full", "custom"), default="custom")
    scan.add_argument("--method", dest="ping_method", choices=("auto", "arp", "icmp"), default="auto")
    add_rdns(scan)
    scan.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    scan.set_defaults(func=cmd_scan)

    domains = sub.add_parser("subdomains", parents=[common], help="enumerate subdomains for a domain")
    domains.add_argument("domain", help="hostname such as example.com")
    domains.add_argument("--method", choices=("passive", "active", "both"), default="both")
    domains.add_argument("--wordlist", metavar="PATH", help="readable subdomain wordlist")
    domains.set_defaults(target=None, rdns=False, func=cmd_subdomains)

    all_command = sub.add_parser("all", parents=[common], help="scan a target and enumerate subdomains when it is a domain")
    all_command.add_argument("target", help="IPv4/CIDR/range, or domain such as example.com")
    all_command.add_argument("-p", "--ports", default="top1000", help="top100, top1000 (ports 1-1000), all, range, or list")
    # Keep the command-line port expression authoritative unless a profile is
    # explicitly selected (quick/standard/full).
    all_command.add_argument("--profile", choices=("quick", "standard", "full", "custom"), default="custom")
    all_command.add_argument("--method", dest="ping_method", choices=("auto", "arp", "icmp"), default="auto")
    add_rdns(all_command)
    all_command.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    all_command.add_argument("--wordlist", metavar="PATH", help="readable subdomain wordlist")
    all_command.set_defaults(func=cmd_all)

    ui_command = sub.add_parser("ui", help="start the local NiceGUI browser interface")
    ui_command.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"), help="bind address (loopback only)")
    ui_command.add_argument("--port", type=int, default=8080, help="HTTP port")
    ui_command.set_defaults(func=cmd_ui, rdns=False)
    return parser


def install_signal_handlers(logger, token: CancellationToken) -> None:
    def interrupt(_signum, _frame):
        logger.warn("interrupt received — cancelling; partial results will be preserved")
        token.cancel()
    signal.signal(signal.SIGINT, interrupt)


def _safety_ack(args, logger) -> bool:
    if args.cmd == "ui" or args.yes or os.environ.get("NETSCOPE_I_KNOW_WHAT_IM_DOING") == "1":
        return True
    target = getattr(args, "target", None) or getattr(args, "domain", "") or ""
    logger.warn("NetScope is for systems you own or have written permission to test.")
    logger.info(f"Target: {target}")
    if not sys.stdin.isatty():
        logger.err("non-interactive run — use --yes or NETSCOPE_I_KNOW_WHAT_IM_DOING=1")
        return False
    try:
        accepted = input("Type 'yes' to continue: ").strip().lower() == "yes"
    except EOFError:
        accepted = False
    if not accepted:
        logger.err("aborted by user")
    return accepted


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        os.environ["NO_COLOR"] = "1"
        U._USE_COLOR = False
    logger = U.StderrLogger(quiet=args.quiet, verbose=args.verbose)
    if not _safety_ack(args, logger):
        return 2
    if args.cmd == "ui":
        return args.func(args, logger)
    try:
        # Validate all fields before the engine is allowed to perform I/O.
        operation = args.cmd
        request = _request_from_args(args, operation)
        ScanEngine(logger=logger).validate_request(request)
        return args.func(args, logger)
    except (ValidationError, ValueError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        logger.err(f"fatal: {exc}")
        if args.verbose:
            traceback.print_exc()
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())

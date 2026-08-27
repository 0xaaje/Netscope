# NetScope v2

![Version](https://img.shields.io/badge/version-2.0.0-35b8e8)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94)
![Interface](https://img.shields.io/badge/interface-NiceGUI-42d392)
![Tests](https://img.shields.io/badge/tests-pytest-f2b84b)

NetScope is a local network reconnaissance toolkit built for authorized
security assessments. It combines IPv4 host discovery, TCP connect scanning,
service and OS identification, subdomain enumeration, structured findings,
and report comparison behind both a command-line interface and a responsive
browser-based dashboard.

The scanner is intentionally non-exploitative: it performs connect-only TCP
checks, bounded banner inspection, DNS queries, and optional ARP discovery on
directly connected networks. An open port is reported as an observation, not
as proof of a vulnerability.

> [!IMPORTANT]
> Use NetScope only on systems you own or have explicit written permission to
> assess. You are responsible for following applicable laws and network policy.

## Highlights

- Safe IPv4 target parsing for single addresses, CIDRs, ranges, and lists
- ICMP discovery with automatic ARP selection only on eligible local networks
- Concurrent TCP connect scanning with configurable workers, timeouts, and rate limits
- Quick, Standard, Full, and Custom scan profiles
- Banner-based service and version identification
- Best-effort OS detection using banner evidence and observed ICMP TTL
- HTTP response and TLS certificate observations
- Passive and active subdomain enumeration
- Structured progress events and cooperative cancellation
- Partial-result preservation when a scan is interrupted
- JSON, text, and self-contained HTML reports
- Report comparison for hosts, ports, services, TLS certificates, and findings
- Local NiceGUI interface bound to `127.0.0.1` by default

## What's new in v2

Version 2 separates the scan engine from the user interfaces, so the CLI and
web application share the same validation, execution, cancellation, and
reporting paths. It also introduces the local operations dashboard, live scan
events, asset inventory, HTML reports, TLS/HTTP observations, report
comparison, persistent local settings, stricter input validation, and safer
ARP fallback behavior.

## Architecture

```text
CLI ─────────┐
             ├── Scan Engine ── Events / Results ── Reports
NiceGUI ─────┘
```

The interface never launches the CLI or parses terminal output. Both entry
points call the reusable engine directly, while worker threads publish
structured events through a thread-safe queue.

## Requirements

- Kali Linux or another Linux environment with Python 3.10+
- `python3-venv`
- The system `ping` command for unprivileged ICMP discovery
- A modern browser for the optional local interface

Node.js, a separate frontend build, and root access for the full application
are not required.

## Installation on Kali Linux

```bash
sudo apt update
sudo apt install python3-full python3-venv

git clone https://github.com/0xaaje/netscope.git
cd netscope

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Start the local interface

```bash
source .venv/bin/activate
python ui.py
```

You can also start it through the main CLI:

```bash
python scanner.py ui
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). The server runs in
browser mode, binds to loopback by default, and keeps settings and reports on
the local filesystem.

### Interface sections

| Section | Purpose |
| --- | --- |
| Dashboard | Saved scan totals, discovered hosts, open ports, findings, recent activity, and running status |
| New Scan | Target, profile, discovery, ports, timeout, workers, rate limit, output, and authorization controls |
| Live Scan | Current phase, progress, elapsed time, discovered hosts, open ports, event log, and cancellation |
| Assets | Searchable and sortable host inventory with detailed technical observations |
| Reports | JSON, text, and HTML viewing, downloads, corrupted-file errors, and confirmed deletion |
| Compare | Differences between two compatible completed reports |
| Settings | Local defaults for theme, profiles, timeouts, workers, output, DNS, banners, and rate limiting |

## Command-line usage

```bash
python scanner.py --help
python scanner.py --version
python scanner.py COMMAND --help
```

| Command | Description |
| --- | --- |
| `ping TARGET` | Discover live IPv4 hosts |
| `port TARGET` | Scan one IPv4 address or resolvable domain |
| `scan TARGET` | Discover hosts, scan ports, and identify services and OS evidence |
| `subdomains DOMAIN` | Run passive, active, or combined subdomain enumeration |
| `all TARGET` | Run network scanning and enumerate subdomains when the target is a domain |
| `ui` | Start the local NiceGUI application |

NetScope asks for authorization confirmation before a CLI scan. For controlled
automation, place `--yes` before the command or set
`NETSCOPE_I_KNOW_WHAT_IM_DOING=1`.

### Examples

Discover a local subnet:

```bash
python scanner.py --yes ping 192.168.1.0/24 --method auto --no-rdns
```

Scan selected ports on one host:

```bash
python scanner.py --yes port 192.168.1.10 --ports 22,80,443 --output output/host
```

Run the Standard profile and create every report format:

```bash
python scanner.py --yes scan 192.168.1.0/24 \
  --profile standard \
  --rate-limit 500 \
  --format all \
  --output output/lan
```

Enumerate subdomains:

```bash
python scanner.py --yes subdomains example.com --method both --output output/domain
```

Run the complete workflow for a domain:

```bash
python scanner.py --yes all example.com --profile quick --output output/example
```

## Scan profiles and port syntax

| Profile | Port coverage |
| --- | --- |
| Quick | Exactly 100 curated TCP service ports |
| Standard | TCP ports 1–1000 |
| Full | TCP ports 1–65535 |
| Custom | A preset, individual ports, ranges, or comma-separated combinations |

Accepted custom examples:

```text
top100
top1000
22,80,443
8000-8100
22,80,443,8000-8100
```

Targets may be a single IPv4 address, CIDR, inclusive range, or comma-separated
list. IPv6 is rejected before network activity because the current discovery
and connection paths are intentionally IPv4-only.

## Discovery and privileges

The application should run as a normal user. In `auto` mode, ARP is used only
when all requested addresses are on a directly connected IPv4 route, Scapy is
available, and the process has the required raw-socket privilege. Otherwise,
NetScope uses the unprivileged ICMP path.

An explicit `--method arp` request fails with a clear dependency or privilege
message when ARP is unavailable. The web server never invokes `sudo`, and the
project does not assign broad capabilities to the Python interpreter.

## Reports

Use `--format` to select the output:

| Value | Files written |
| --- | --- |
| `json` | `report.json` only |
| `text` | `report.txt` only |
| `both` | `report.json` and `report.txt` |
| `html` | `report.html` only |
| `all` | JSON, text, and HTML |

JSON reports use schema version 2 and retain the original host, port, service,
OS, and subdomain structures. They also record scan status, coverage,
warnings, errors, HTTP/TLS observations, evidence-based findings, timestamps,
and duration.

HTML reports are self-contained, use inline styling, require no CDN, and
escape network-derived content. Findings include severity, affected host and
port, direct evidence, classification, confidence, and practical remediation.

Comparisons are conservative. NetScope reports a change only when both scans
completed successfully and the later scan provides sufficient coverage;
cancelled or incomplete scans remain indeterminate.

## Local settings

On Kali Linux, interface settings are stored in:

```text
~/.config/netscope/settings.json
```

Only non-secret preferences are stored. Scan results are written to the
configured output directory, which defaults to `output/`.

## Project structure

```text
netscope/
├── scanner.py                 # CLI entry point
├── ui.py                      # Local NiceGUI application
├── modules/
│   ├── engine.py              # Shared scan orchestration and events
│   ├── ping_sweep.py          # ICMP and ARP discovery
│   ├── port_scanner.py        # TCP connect scanning and observations
│   ├── service_detect.py      # Service and OS heuristics
│   ├── subdomain_enum.py      # Passive and active enumeration
│   ├── exporter.py            # JSON, text, and HTML reports
│   ├── comparison.py          # Report comparison
│   ├── ui_state.py            # UI form and live-state validation
│   ├── settings.py            # Local settings persistence
│   └── utils.py               # Shared parsing and validation
├── tests/                     # Deterministic pytest suite
├── requirements.txt           # Runtime dependencies
└── requirements-dev.txt       # Development dependencies
```

## Development

```bash
python -m pip install -r requirements-dev.txt
pytest -q
ruff check .
python -m compileall -q .
```

The test suite uses mocks and deterministic fixtures. It does not scan
external systems.

## Limitations

- IPv6 and UDP scanning are not implemented.
- OS and service detection are evidence-based heuristics, not authoritative fingerprinting.
- Passive subdomain discovery requires internet access to query certificate-transparency data.
- DNS resolution duration can depend on the operating system resolver.
- In-flight socket operations may continue until their configured timeout after cancellation.
- Full-profile scans are intentionally expensive and should be rate-limited on larger targets.

## Responsible use

NetScope is intended for defensive administration, asset discovery,
laboratory work, and explicitly authorized security testing. Do not use it to
probe third-party infrastructure without permission.

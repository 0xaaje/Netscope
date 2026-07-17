# NetScope

> Network Scanner & Reconnaissance Toolkit for **authorized** testing on
> networks you own or have written permission to assess.
> Designed for **Kali Linux** (and any Python 3.9+ POSIX system).

NetScope is a single-file-CLI tool with a small set of focused modules:

| Module             | What it does                                                      |
|--------------------|-------------------------------------------------------------------|
| `ping_sweep`       | ICMP or ARP host discovery (multi-threaded)                       |
| `port_scanner`     | Multi-threaded TCP connect scan + banner grabbing                 |
| `service_detect`   | OS & service version guesses parsed from banners                  |
| `subdomain_enum`   | crt.sh (passive) and/or wordlist (active) subdomain enumeration  |
| `exporter`         | JSON + human-readable text report                                 |

It is **connect-only TCP** and a **banner-only** fingerprinter — no exploit
payloads, no raw SYN scans, no crafted probes. It is intentionally quieter
than nmap so it stays portable and audit-friendly.

---

## 1. Directory layout

```
netscope/
├── scanner.py              # main CLI (argparse, all subcommands)
├── requirements.txt        # optional deps (scapy, requests)
├── modules/
│   ├── __init__.py
│   ├── utils.py            # color, parsing, port presets, logger
│   ├── ping_sweep.py       # ICMP / ARP
│   ├── port_scanner.py     # TCP connect + banner grab
│   ├── service_detect.py   # banner → service/OS guess
│   ├── subdomain_enum.py   # crt.sh + wordlist
│   └── exporter.py         # JSON + text reports
├── wordlists/
│   └── subdomains.txt      # ~200-entry starter list (auto-created)
├── output/                 # reports land here when -o is used
└── logs/                   # reserved for future log files
```

---

## 2. Install (Kali Linux)

```bash
# 1. Get the code
git clone <your-repo-url> netscope
cd netscope

# 2. (Recommended) virtualenv so system Python stays clean
python3 -m venv .venv
source .venv/bin/activate

# 3. Optional deps
#    - scapy   → enables ARP sweep (faster, finds ICMP-blocked hosts)
#    - requests → enables crt.sh passive subdomain enum
#    Both are listed in requirements.txt:
pip install -r requirements.txt

# 4. Make the launcher executable (optional)
chmod +x scanner.py
```

The tool runs on stdlib alone if you skip `pip install` — but you'll lose
ARP sweep and crt.sh.

### Raw sockets & sudo

| Operation                | Needs root? | Why                                           |
|--------------------------|-------------|-----------------------------------------------|
| ICMP ping sweep          | sometimes   | Some kernels only allow unprivileged ICMP for limited sizes; on Kali, plain user works. |
| ARP sweep (scapy)        | **yes**     | Raw L2 frames require `CAP_NET_RAW`.          |
| TCP connect scan         | no          | Plain `connect()` — no raw sockets.           |
| Banner grab              | no          | Just a socket read.                           |
| DNS / crt.sh             | no          | Outbound HTTP + DNS only.                     |

**Run the full scan with sudo for best results:**

```bash
sudo python3 scanner.py scan 192.168.1.0/24 -o output/home
```

A non-root run is fine; you'll just get ICMP sweep instead of ARP.

---

## 3. Usage

```text
python3 scanner.py <command> [options] <target>
```

### Commands at a glance

| Command      | Purpose                                                  |
|--------------|----------------------------------------------------------|
| `ping`       | host discovery only (no port scan)                       |
| `port`       | TCP port scan of a single host                           |
| `scan`       | discover + TCP port scan + service/OS detection          |
| `subdomains` | enumerate subdomains of a domain                         |
| `all`        | `scan` + (if target is a domain) subdomain enumeration   |

### Common flags

```
  -t / --timeout FLOAT   per-probe timeout in seconds (default 1.5)
  -w / --workers  INT    concurrent workers (default 200)
  -o / --output   DIR    write JSON+text report into DIR
  -f / --format   FMT    json | text | both (default both)
  -q / --quiet           suppress info-level stderr
  -v / --verbose         debug-level stderr
  --no-color             disable ANSI color
```

### Examples

```bash
# 1. Discover live hosts on the LAN (with reverse DNS)
sudo python3 scanner.py ping 192.168.1.0/24 --rdns -o output/lan

# 2. Top-1000 port scan of a single host, no banners (faster)
python3 scanner.py port 192.168.1.10 --ports top1000 --no-banner

# 3. Full scan of a /24 with everything on
sudo python3 scanner.py scan 192.168.1.0/24 --ports top1000 -o output/home

# 4. Custom port list (SSH, HTTP, HTTPS, RDP, MySQL, RDP)
python3 scanner.py port 10.0.0.5 --ports 22,80,443,3306,3389 -o output/dbhost

# 5. Subdomain enum (crt.sh + bundled wordlist)
python3 scanner.py subdomains example.com -o output/example

# 6. Passive only (crt.sh) — no DNS load
python3 scanner.py subdomains example.com --method passive

# 7. Use a custom wordlist
python3 scanner.py subdomains example.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 8. All-in-one against a domain
sudo python3 scanner.py all example.com --ports top1000 -o output/example_full
```

### Safety prompt

The first time you run a target, NetScope asks:

```
Type 'yes' to continue, anything else to abort:
```

In CI / non-interactive shells, set:

```bash
export NETSCOPE_I_KNOW_WHAT_IM_DOING=1
```

---

## 4. Output

With `-o output/run1`, two files are written:

```
output/run1/
├── report.json   # machine-readable, complete record
└── report.txt    # human-readable, paste-friendly summary
```

`report.json` is a single object with this shape:

```jsonc
{
  "meta":   { "tool": "NetScope", "version": "1.0.0",
              "target": "192.168.1.0/24",
              "started_at": "...", "finished_at": "...",
              "duration_s": 12.34, "scan": { ... } },
  "hosts":  [ { "ip": "...", "alive": true, "mac": "...", ... } ],
  "alive_hosts": [ "192.168.1.1", ... ],
  "port_results":     { "192.168.1.10": [ { "port": 22, "open": true, ... } ] },
  "service_guesses":  { "192.168.1.10": [ { "product": "OpenSSH", "version": "8.9p1" } ] },
  "os_guesses":       { "192.168.1.10": { "family": "Linux", ... } },
  "subdomains":       [ { "subdomain": "www.example.com", "ips": [...], ... } ]
}
```

---

## 5. Performance notes

- Default worker counts (200 for ports, 128 for ICMP, 32 for DNS) are
  tuned for a Linux loopback / lab network. On noisy networks raise
  `--timeout` and lower `--workers`; on a fast LAN you can raise both.
- ARP sweep is much faster than ICMP on a /24 because it doesn't wait
  for the kernel's ICMP rate-limiter.
- Banner grabbing has its own 1.5s read budget per port. Use
  `--no-banner` for raw speed when you only need port state.

---

## 6. Limitations

- This is **not** nmap. OS detection is banner-based, not TCP/IP stack
  fingerprinting. Service version detection is regex-based and
  approximate.
- No UDP scanning (would need raw sockets, slow, easily missed).
- No IDS/IPS evasion (no fragmentation, no decoys). Don't point this at
  production networks.
- The crt.sh endpoint can rate-limit or be slow. Treat it as
  best-effort.

---

## 7. Legal

Run NetScope **only** against systems you own or have explicit written
permission to test. Unauthorized port scanning, banner grabbing, and
subdomain enumeration can violate computer-misuse laws in many
jurisdictions (e.g. CFAA in the US, Computer Misuse Act in the UK, and
similar laws elsewhere). The authors of NetScope accept no liability
for misuse.

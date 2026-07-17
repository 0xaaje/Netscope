"""NetScope - subdomain enumeration.

Two strategies, both opt-in:
  - Passive: query crt.sh (a Certificate Transparency log aggregator).
    Stealth, no DNS load on the target, but only finds subdomains that
    have ever appeared in a public CT log.
  - Active: brute-force a small wordlist against the target's DNS.
    Louder, requires DNS to be reachable, but catches subdomains with
    no public cert history (internal dev hosts, brand-new boxes, etc.).

The active wordlist is small by default (~200 entries) and tunable via
--wordlist <path>. A minimal built-in list ships with the tool.
"""
from __future__ import annotations

import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

from .utils import cyan, dim, green, red, yellow


# --- Result type ------------------------------------------------------------

@dataclass
class SubdomainHit:
    subdomain: str
    source: str       # "crt.sh" | "bruteforce"
    ips: List[str]
    alive: bool

    def to_dict(self) -> dict:
        return asdict(self)


# --- Built-in wordlist (small but useful) ---------------------------------

# Kept as a single set, deduplicated, sorted. Edit freely, or supply
# your own via --wordlist <path>. This is ~200 entries covering the
# obvious prefixes that real-world subdomains tend to use.
_BUILTIN_SUBDOMAINS = sorted(set("""
www mail ftp smtp pop pop3 imap imap4 webmail email
mx mx1 mx2 ns ns1 ns2 ns3 dns dns1 dns2
vpn remote gateway gw ssl secure
admin administrator panel cpanel whm plesk webmin
api api2 apiv1 rest graphql
app apps application web web1 web2 www2
dev development staging stage test qa uat sandbox demo
beta canary preview nightly
blog wp wordpress joomla drupal
shop store ecommerce cart
docs documentation wiki help support helpdesk ticket tickets
jira confluence bitbucket gitlab github git
git1 gitea
status monitor monitoring grafana prometheus alert alerts
logs log kibana
cdn cdn1 cdn2 static assets media img images
download downloads files upload uploads
backup backups db database mysql postgres postgresql
redis mongo mongodb elasticsearch
mail2 webmail2 smtp2 imap2
auth sso login signin sso2 oauth
sandbox lab labs research
intranet portal hr jobs careers recruiting
shop store pay payment billing invoice
crm erp sap oracle
m m1 mobile mweb
tv video stream live radio podcast
ns4 ns5 vpn2 remote2 access
api1 api3 api-v1 api-v2
ci cd jenkins bamboo build builds buildbot
docker registry k8s kubernetes helm
ftp2 sftp fileserver nas
test1 test2 dev1 dev2 stage1
internal corp corporate intranet1
www1 www-old old legacy
admin1 admin2 panel2
shop1 store1 pay1
""".split()))


def default_wordlist_path() -> str:
    """Path to the bundled wordlist file (always written on first use)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "wordlists", "subdomains.txt"))


def ensure_default_wordlist() -> str:
    """Write the built-in wordlist to disk if it doesn't exist yet.
    Returns the path."""
    path = default_wordlist_path()
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(_BUILTIN_SUBDOMAINS) + "\n")
    return path


def load_wordlist(path: Optional[str]) -> List[str]:
    """Load a wordlist from disk, or fall back to the bundled default."""
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [w.strip() for w in f if w.strip() and not w.startswith("#")]
    ensure_default_wordlist()
    return list(_BUILTIN_SUBDOMAINS)


# --- Public entry point -----------------------------------------------------

def enumerate_subdomains(
    domain: str,
    *,
    method: str = "both",     # "passive" | "active" | "both"
    wordlist: Optional[str] = None,
    workers: int = 32,
    timeout: float = 2.0,
    logger=None,
) -> List[SubdomainHit]:
    """Enumerate subdomains for `domain`.  Returns deduped hits."""
    if logger is None:
        from .utils import StderrLogger
        logger = StderrLogger()

    domain = (domain or "").strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").split("/", 1)[0]
    if not domain or "." not in domain:
        logger.err(f"invalid domain: {domain!r}")
        return []

    logger.info(f"subdomain enum for {domain} — method={method}")

    found: dict = {}  # subdomain -> SubdomainHit (later sources overwrite)

    if method in ("passive", "both"):
        for hit in _crtsh_enum(domain, logger=logger):
            found[hit.subdomain] = hit

    if method in ("active", "both"):
        words = load_wordlist(wordlist)
        logger.info(f"active brute force — {len(words)} candidates")
        socket.setdefaulttimeout(timeout)
        try:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {
                    ex.submit(_resolve, f"{w}.{domain}"): f"{w}.{domain}"
                    for w in words
                }
                for fut in as_completed(futures):
                    fqdn = futures[fut]
                    try:
                        ips = fut.result() or []
                    except Exception:
                        ips = []
                    if ips:
                        if fqdn not in found:
                            found[fqdn] = SubdomainHit(
                                subdomain=fqdn, source="bruteforce",
                                ips=ips, alive=True,
                            )
                        else:
                            found[fqdn].ips = list(set(found[fqdn].ips) | set(ips))
                            found[fqdn].alive = True
        finally:
            socket.setdefaulttimeout(None)

    hits = sorted(found.values(), key=lambda h: h.subdomain)
    logger.ok(f"{len(hits)} subdomain(s) found for {domain}")
    for h in hits:
        marker = green("ALIVE") if h.alive else dim("seen ")
        ips = ",".join(h.ips[:3])
        if len(h.ips) > 3:
            ips += f" (+{len(h.ips)-3})"
        logger.ok(f"  {marker}  {h.subdomain:<40s}  {dim(ips)}  {dim('[' + h.source + ']')}")
    return hits


# --- Passive: crt.sh --------------------------------------------------------

def _crtsh_enum(domain: str, *, logger, timeout: float = 15.0) -> List[SubdomainHit]:
    """Query crt.sh for CT logs mentioning `domain`."""
    try:
        import requests
    except ImportError:
        logger.warn("requests not installed — skipping crt.sh (pip install requests)")
        return []

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info(f"GET {url}")
    try:
        r = requests.get(url, timeout=timeout)
    except Exception as exc:
        logger.warn(f"crt.sh request failed: {exc}")
        return []

    if r.status_code != 200:
        logger.warn(f"crt.sh returned HTTP {r.status_code}")
        return []

    try:
        rows = r.json()
    except json.JSONDecodeError:
        logger.warn("crt.sh returned non-JSON (rate-limited?)")
        return []

    found: Set[str] = set()
    for row in rows:
        for fld in ("name_value", "common_name"):
            v = (row.get(fld) or "").strip().lower()
            if not v:
                continue
            for sub in v.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith("." + domain) or sub == domain:
                    found.add(sub)

    logger.info(f"crt.sh: {len(found)} unique name(s)")
    hits: List[SubdomainHit] = []
    for sub in sorted(found):
        ips = _resolve(sub) or []
        hits.append(SubdomainHit(
            subdomain=sub, source="crt.sh", ips=ips, alive=bool(ips),
        ))
    return hits


# --- Active resolve --------------------------------------------------------

def _resolve(fqdn: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(fqdn, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and sockaddr[0]:
            out.append(sockaddr[0])
    return sorted(set(out))

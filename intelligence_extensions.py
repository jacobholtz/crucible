"""
Helper functions for extended threat intelligence gathering.
This module contains extensions for:
- Shodan historical IP/port data
- VirusTotal passive DNS lookups
- Expanded phishing kit fingerprints
- Multi-platform IOC correlation
- Recursive subdomain discovery
"""

import asyncio
import datetime as _dt
import httpx
import ipaddress
import os
import re
from typing import Optional, List, Dict, Any


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_ts(value) -> str:
    """Coerce any timestamp shape to an ISO-8601 string (UTC).

    External TI sources return timestamps in incompatible types:
      * VirusTotal — `attributes.date` as Unix-epoch int
      * OTX        — ISO strings ("2024-12-01T10:00:00") most of the time
      * ThreatFox  — ISO strings with a space separator
      * Shodan     — Unix-epoch float
      * URLScan    — ISO strings, sometimes None

    Comparing these directly raises TypeError once one source returns int
    and another returns str. Normalising at every fetcher boundary fixes the
    cross-source `<`/`>` crash AND gives chronologically-correct ordering
    when string-compared (ISO timestamps sort lexicographically).
    """
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        # Heuristic: anything < 10^11 is seconds, otherwise milliseconds.
        secs = float(value) / 1000.0 if value >= 1e11 else float(value)
        try:
            return _dt.datetime.fromtimestamp(secs, tz=_dt.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (OverflowError, OSError, ValueError):
            return str(value)
    # Strings: best-effort normalise common shapes.
    s = str(value).strip()
    if not s:
        return ""
    # ThreatFox uses "YYYY-MM-DD HH:MM:SS UTC" — flip the space for ISO.
    if len(s) >= 19 and s[10] == " ":
        s = s[:10] + "T" + s[11:]
    return s


async def fetch_shodan_data(ip: str, api_key: str) -> dict:
    """Fetch Shodan data for historical ports and device information."""
    if not api_key:
        return {"error": "Shodan API key not configured"}
    
    base_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(base_url, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                ports = data.get("ports", [])
                isp = data.get("isp", "")
                org = data.get("org", "")
                os_info = data.get("os", "")
                
                # Historical IP addresses from DNS + JARM fingerprints from
                # the per-service records. JARM is a pivot primitive the major
                # platforms key on; we'd otherwise discard it when trimming.
                historical_ips = []
                jarms = []
                if "data" in data and data["data"]:
                    for entry in data["data"]:
                        if "domains" in entry:
                            historical_ips.extend(entry["domains"])
                        jarm = (entry.get("ssl") or {}).get("jarm")
                        if jarm:
                            jarms.append({"port": entry.get("port"), "jarm": jarm})

                result = {
                    "ip": ip,
                    "organization": org,
                    "isp": isp,
                    "os": os_info,
                    "open_ports": ports,
                    "historical_dns": list(set(historical_ips)) if historical_ips else [],
                    "jarms": jarms,
                }
                return result
            else:
                return {"error": f"Shodan API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"Shodan fetch failed: {str(e)}"}


async def fetch_virustotal_reputation(seed: str, api_key: str) -> dict:
    """
    Fetch VirusTotal reputation summary for a domain or IP — vendor verdict
    counts from `last_analysis_stats` plus the overall reputation score and a
    verdict.

    IP seeds → /api/v3/ip_addresses/{ip}, permalink uses gui/ip-address/{ip}.
    Domain seeds → /api/v3/domains/{domain}, permalink uses gui/domain/{domain}.

    Returns a dict with: seed identity ("domain" or "ip"), malicious,
    suspicious, harmless, undetected, timeout, total, reputation,
    verdict ('malicious' | 'suspicious' | 'clean'), permalink. On API/network
    failure, returns an `error` key — callers should treat it as "unknown"
    rather than "clean."
    """
    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    seed_is_ip = _is_ip(seed)
    if seed_is_ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{seed}"
        permalink = f"https://www.virustotal.com/gui/ip-address/{seed}"
        identity_key = "ip"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{seed}"
        permalink = f"https://www.virustotal.com/gui/domain/{seed}"
        identity_key = "domain"

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=15.0)
            if response.status_code == 404:
                return {identity_key: seed, "verdict": "unknown",
                        "malicious": 0, "suspicious": 0, "harmless": 0,
                        "undetected": 0, "timeout": 0, "total": 0,
                        "reputation": 0,
                        "permalink": permalink,
                        "not_found": True}
            if response.status_code != 200:
                return {"error": f"VirusTotal API error: {response.status_code}"}
            attrs = (response.json().get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)
            timeout = int(stats.get("timeout", 0) or 0)
            total = malicious + suspicious + harmless + undetected + timeout
            verdict = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean")
            return {
                identity_key: seed,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout,
                "total": total,
                "reputation": int(attrs.get("reputation", 0) or 0),
                "verdict": verdict,
                "permalink": permalink,
            }
    except Exception as e:
        return {"error": f"VirusTotal fetch failed: {str(e)}"}


async def fetch_virustotal_passive_dns(seed: str, api_key: str) -> dict:
    """
    Fetch passive DNS records from VirusTotal.

    Domain seeds → /domains/{d}/resolutions   → returns historical IPs that
                                                 resolved to the domain.
    IP seeds     → /ip_addresses/{ip}/resolutions → returns historical domains
                                                    that resolved to the IP.

    Hitting the wrong collection (e.g., sending an IP to the domains endpoint)
    returns a 404 and silently drops the pivot surface, so route by seed type.
    """
    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    seed_is_ip = _is_ip(seed)
    if seed_is_ip:
        base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{seed}/resolutions"
    else:
        base_url = f"https://www.virustotal.com/api/v3/domains/{seed}/resolutions"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(base_url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                resolutions = data.get("data", [])

                if seed_is_ip:
                    # IP seed: each resolution carries a host_name (historical domain).
                    domain_history = []
                    for res in resolutions:
                        attributes = res.get("attributes", {})
                        host = attributes.get("host_name", "")
                        last_resolved = _normalize_ts(
                            attributes.get("date") or attributes.get("last_resolved")
                        )
                        if host:
                            domain_history.append({
                                "domain": host,
                                "last_resolved": last_resolved
                            })
                    return {
                        "ip": seed,
                        "passive_dns_count": len(domain_history),
                        "domain_history": domain_history,
                    }

                # Domain seed: each resolution carries an ip_address (historical IP).
                ip_history = []
                for res in resolutions:
                    attributes = res.get("attributes", {})
                    ip_address = attributes.get("ip_address") or res.get("id", "").split(":")[-1]
                    last_resolved = _normalize_ts(
                        attributes.get("date") or attributes.get("last_resolved")
                    )
                    ip_history.append({
                        "ip": ip_address,
                        "last_resolved": last_resolved
                    })
                return {
                    "domain": seed,
                    "passive_dns_count": len(ip_history),
                    "ip_history": ip_history,
                }
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal fetch failed: {str(e)}"}


# Expanded phishing kit fingerprints
EXPANDED_PHISHING_PATTERNS = [
    # Existing DSJ operation patterns
    "dsj", 
    "dsjexchange", 
    "bgwealth", 
    "bggrace", 
    "copypasteandconfirm", 
    "bgwealthalert", 
    "wxpass", 
    "ddjea", 
    "ddjeb",
    "dsjhout", 
    "neibu",
    
    # New pig-butchering scams
    "wealth", 
    "invest",
    "profit",
    "fxtrad",
    "bitco",
    "ethereum",
    "crypt",
    "trader",
    "broker",
    "market",
    
    # Common financial operation suffixes
    "wealth",
    "income",
    "profit",
    "fx",
    "trade",
    "capital",
    "fund",
    "group",
    "finance",
    "trading",
    "exchange",
    
    # Suspicious domain patterns often used in financial scams
    "vip",
    "promo",
    "limited",
    "secure",
    "account",
    "login",
    "wallet",
    "connect",
    "app",
    "portal",
    "dashboard",
]


# A line counts as a hosted domain only if it actually looks like one — HackerTarget
# returns plain-text status messages (HTTP 200) for empty results / quota / errors,
# and those must not be mistaken for domains.
_RIP_DOMAIN_RE = re.compile(r'^(?:[a-z0-9_-]+\.)+[a-z]{2,}$', re.IGNORECASE)
_HT_NONRESULT_MARKERS = (
    "no dns a records", "no records", "api count exceeded", "error",
    "invalid", "not found", "increase quota",
)

async def fetch_reverse_ip_lookup(ip: str) -> dict:
    """
    Fetch reverse IP lookup data to find all domains hosted on the same IP.
    Uses HackerTarget's free reverse-IP API (one domain per line). The free tier is
    rate-limited and, when empty or throttled, returns a human-readable message rather
    than a domain list — those are detected and reported as 0 domains (not a fake one).
    """
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=15.0)
        if response.status_code != 200:
            return {"error": f"HackerTarget API error: {response.status_code}"}

        text = (response.text or "").strip()
        low = text.lower()
        # Whole-response status message (e.g. "No DNS A records found",
        # "API count exceeded ...") → genuinely no usable domains.
        if not text or (any(m in low for m in _HT_NONRESULT_MARKERS) and "\n" not in text):
            return {"ip": ip, "domains": [], "count": 0, "source": "hackertarget",
                    "note": text[:160] or "empty response"}

        # Keep only lines that actually parse as a domain.
        domains = []
        for line in text.split("\n"):
            d = line.strip().lower().rstrip(".")
            if _RIP_DOMAIN_RE.match(d):
                domains.append(d)
        return {"ip": ip, "domains": domains, "count": len(domains), "source": "hackertarget"}
    except Exception as e:
        return {"error": f"Reverse IP lookup failed: {str(e)}"}


async def fetch_subdomain_enumeration(domain: str, vt_api_key: str = "") -> dict:
    """
    Subdomain enumeration via four parallel sources:
      1. Certificate Transparency (crt.sh + certspotter)
      2. VirusTotal /domains/{d}/subdomains relationships (skipped if no key)
      3. HTML referenced hosts (homepage + robots.txt + sitemap.xml scrape)
      4. DNS brute force against a common-prefix wordlist

    Sources run concurrently. Each subdomain is attributed to every source
    that surfaced it (see `evidence`). Filtered with a label-anchored suffix
    check so `notexample.com` can't be mistaken for a subdomain of `example.com`.
    """
    dom_lc = domain.lower()
    suffix = "." + dom_lc

    try:
        async with httpx.AsyncClient() as _c:
            wildcard_ips = await detect_wildcard_dns(_c, domain)

        tasks = [
            fetch_ct_subdomains(domain),
            dns_brute_force(domain),
            fetch_html_referenced_hosts(domain),
        ]
        if vt_api_key:
            tasks.append(fetch_virustotal_subdomains(domain, vt_api_key))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ct_raw, brute_raw, html_raw = results[0], results[1], results[2]
        vt_raw = results[3] if vt_api_key else set()

        def _label_anchored(x) -> set:
            if not isinstance(x, set):
                return set()
            return {s.lower() for s in x if s.lower().endswith(suffix)}

        ct_subdomains    = _label_anchored(ct_raw)
        brute_subdomains = _label_anchored(brute_raw)
        html_subdomains  = _label_anchored(html_raw)
        vt_subdomains    = _label_anchored(vt_raw)

        clean_subdomains = sorted(
            ct_subdomains | brute_subdomains | html_subdomains | vt_subdomains
        )

        # Per-subdomain provenance: every source that surfaced it.
        evidence: dict = {}
        for s in ct_subdomains:    evidence.setdefault(s, []).append("cert-transparency")
        for s in vt_subdomains:    evidence.setdefault(s, []).append("virustotal-passive-dns")
        for s in html_subdomains:  evidence.setdefault(s, []).append("html-scrape")
        for s in brute_subdomains: evidence.setdefault(s, []).append("dns-brute-force")

        admin_interfaces = identify_admin_interfaces(clean_subdomains)
        for a in admin_interfaces:
            a["evidence"] = ",".join(evidence.get(a["subdomain"], ["unknown"]))

        internal_infra = identify_internal_infrastructure(clean_subdomains)

        # Coverage warning: brute force doesn't count as a "reliable" source
        # for non-generic hostnames (it can't guess company names). If none of
        # the evidence-based sources found anything, surface why so the caller
        # doesn't mistake "no subdomains discovered" for "domain is isolated."
        warning = None
        if (not vt_api_key
                and not ct_subdomains
                and not html_subdomains):
            warning = (
                "No subdomains discovered via CT or HTML scrape, and VirusTotal "
                "passive DNS was not enabled (no VIRUSTOTAL_API_KEY). Subdomains "
                "served via Cloudflare Universal SSL or with apex that doesn't "
                "host content typically need passive DNS for discovery — set "
                "VIRUSTOTAL_API_KEY and re-run."
            )

        return {
            "domain": domain,
            "subdomains": clean_subdomains,
            "subdomain_count": len(clean_subdomains),
            "ct_verified_count": len(ct_subdomains),
            "vt_passive_dns_count": len(vt_subdomains),
            "html_referenced_count": len(html_subdomains),
            "brute_force_count": len(brute_subdomains),
            "evidence": {s: sorted(set(srcs)) for s, srcs in evidence.items()},
            "wildcard_dns": bool(wildcard_ips),
            "admin_interfaces": admin_interfaces,
            "internal_infrastructure": internal_infra,
            "vt_enabled": bool(vt_api_key),
            "warning": warning,
            "source": "recursive_discovery",
        }
    except Exception as e:
        return {"error": f"Subdomain enumeration failed: {str(e)}"}


async def fetch_ct_subdomains(domain: str) -> set:
    """
    Fetch subdomains from Certificate Transparency logs (crt.sh + certspotter).
    Returns label-anchored, lowercase hostnames. The apex itself is excluded —
    the orchestrator only wants subdomains.
    """
    subdomains: set = set()
    dom_lc = domain.lower()
    suffix = "." + dom_lc

    def _accept(name: str) -> None:
        clean = name.strip().lstrip("*.").lower()
        if clean and clean.endswith(suffix):
            subdomains.add(clean)

    ct_sources = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        f"&include_subdomains=true&expand=dns_names",
    ]

    for url in ct_sources:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=15.0)
                if response.status_code != 200:
                    continue
                data = response.json()
                if not isinstance(data, list):
                    continue
                for entry in data:
                    if "name_value" in entry:    # crt.sh
                        for name in entry["name_value"].split():
                            _accept(name)
                    elif "dns_names" in entry:   # certspotter
                        for name in entry["dns_names"]:
                            _accept(name)
        except Exception:
            continue  # try next source

    return subdomains


_HOST_IN_URL = re.compile(rb"https?://([A-Za-z0-9.\-]+)", re.IGNORECASE)


async def fetch_virustotal_subdomains(domain: str, api_key: str, max_pages: int = 5) -> set:
    """
    Pull subdomains via VirusTotal's /domains/{d}/subdomains relationships
    endpoint. Distinct from fetch_virustotal_passive_dns above, which returns
    historical IP resolutions for the domain — this endpoint enumerates
    subdomain hostnames VT has observed (passive DNS + crawl).

    Paginates up to max_pages * 40 results. Returns label-anchored, lowercase
    hostnames. Empty set on auth failure or transport error.
    """
    if not api_key:
        return set()
    dom_lc = domain.lower()
    suffix = "." + dom_lc
    subdomains: set = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            for _ in range(max_pages):
                r = await client.get(url, headers=headers)
                if r.status_code != 200:
                    break
                data = r.json()
                for entry in (data.get("data") or []):
                    sub = (entry.get("id") or "").strip().lower().lstrip("*.")
                    if sub.endswith(suffix):
                        subdomains.add(sub)
                next_url = (data.get("links") or {}).get("next")
                if not next_url:
                    break
                url = next_url
    except Exception:
        pass
    return subdomains


async def fetch_html_referenced_hosts(domain: str, timeout_s: float = 8.0) -> set:
    """
    Scrape the apex homepage + robots.txt + sitemap.xml (and the www. variant)
    and extract any hostname under the same registrable. Catches subdomains
    that are publicly referenced but never made it into a CT log — the
    canonical Cloudflare-Universal-SSL coverage gap.

    Cheap: no API key, four parallel fetches with an 8 s budget each. Bodies
    are capped at 1 MB. Returns label-anchored, lowercase hostnames.
    """
    dom_lc = domain.lower()
    suffix = "." + dom_lc
    found: set = set()
    headers = {"User-Agent": "crucible/1.0 (+threat-intel)"}
    candidates = [
        f"https://{domain}/",
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml",
        f"https://www.{domain}/",
    ]

    try:
        async with httpx.AsyncClient(timeout=timeout_s, headers=headers,
                                     follow_redirects=True) as client:
            responses = await asyncio.gather(
                *(client.get(u) for u in candidates),
                return_exceptions=True,
            )
            for r in responses:
                if isinstance(r, Exception):
                    continue
                if r.status_code >= 400:
                    continue
                body = r.content[:1_000_000]
                for m in _HOST_IN_URL.finditer(body):
                    host = m.group(1).decode("ascii", "replace").lower()
                    if host == dom_lc or host == f"www.{dom_lc}":
                        continue
                    if host.endswith(suffix):
                        found.add(host)
    except Exception:
        pass

    return found


async def dns_brute_force(domain: str) -> set:
    """
    Perform DNS brute force enumeration using common subdomain names.
    """
    subdomains = set()
    # Common subdomain prefixes
    common_prefixes = [
        "www", "api", "admin", "panel", "portal", "mail", "ftp", "dev", "staging",
        "test", "beta", "alpha", "blog", "shop", "store", "support", "help",
        "docs", "wiki", "forum", "status", "m", "mobile", "app", "apps",
        "secure", "login", "auth", "oauth", "sso", "vpn", "remote", "dashboard",
        "stats", "analytics", "monitor", "internal", "private", "local", "demo",
        "backup", "db", "database", "mysql", "postgres", "mongo", "redis",
        "stage", "stg", "prod", "production", "devops", "jenkins", "git", "svn",
        "ns1", "ns2", "dns1", "dns2", "mx1", "mx2", "smtp", "pop", "imap",
        "cpanel", "webmail", "whm", "autodiscover", "autoconfig", "sip", "xmpp",
        "irc", "chat", "cdn", "assets", "img", "images", "static", "css", "js",
        "media", "video", "audio", "download", "files", "file", "docs", "doc",
        "upload", "uploads", "share", "sharing", "drive", "cloud", "s3", "aws",
        "azure", "gcp", "google", "microsoft", "facebook", "twitter", "linkedin",
        "neibu", "manager", "manage", "operator", "kyc", "control", "config",
        "settings", "setup", "install", "update", "upgrade", "maintenance"
    ]
    
    try:
        async with httpx.AsyncClient() as client:
            # Detect wildcard DNS first: if *.domain resolves, brute force is unreliable
            # (every guessed name "resolves") — so we exclude names that only resolve to
            # the wildcard IPs. This kills the admin./panel./neibu. false positives.
            wildcard_ips = await detect_wildcard_dns(client, domain)

            tasks = [check_dns_resolution(client, f"{p}.{domain}") for p in common_prefixes[:50]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, tuple):
                    sub, ips = result
                    if not sub:
                        continue
                    # Keep only if it resolves to at least one IP that ISN'T the wildcard.
                    if wildcard_ips and ips and ips.issubset(wildcard_ips):
                        continue
                    subdomains.add(sub)
    except Exception:
        pass  # Continue with other methods

    return subdomains


async def _resolve_a(client, name: str) -> set:
    """Return the set of A-record IPs a name resolves to (empty set if none)."""
    try:
        r = await client.get(f"https://dns.google/resolve?name={name}&type=A", timeout=5.0)
        if r.status_code == 200:
            return {a["data"] for a in (r.json().get("Answer") or [])
                    if a.get("type") == 1 and a.get("data")}
    except Exception:
        pass
    return set()


async def detect_wildcard_dns(client, domain: str) -> set:
    """Probe two random, almost-certainly-nonexistent subdomains. Any IPs they resolve
    to are the domain's wildcard answer — brute-force hits on only those IPs are noise."""
    import random, string
    wildcard = set()
    for _ in range(2):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        wildcard |= await _resolve_a(client, f"{rand}.{domain}")
    return wildcard


async def check_dns_resolution(client, subdomain: str):
    """Check if a subdomain resolves. Returns (subdomain, set_of_ips) or ("", set())."""
    ips = await _resolve_a(client, subdomain)
    return (subdomain, ips) if ips else ("", set())


async def recursive_subdomain_discovery(subdomains: list, base_domain: str) -> set:
    """
    Perform recursive subdomain discovery by checking newly discovered subdomains.
    """
    recursive_subs = set()
    try:
        # Limit recursion to avoid excessive API calls
        for subdomain in subdomains[:20]:  # Limit to first 20 subdomains
            # Extract potential new base for enumeration
            parts = subdomain.split('.')
            if len(parts) > 2:
                # Try enumerating from the subdomain itself
                ct_subs = await fetch_ct_subdomains(subdomain)
                recursive_subs.update(ct_subs)
                
                # Also try DNS brute force on the subdomain
                brute_subs = await dns_brute_force(subdomain)
                recursive_subs.update(brute_subs)
                
                # Add a small delay to avoid rate limiting
                await asyncio.sleep(0.1)
    except Exception:
        pass
    return recursive_subs


def identify_admin_interfaces(subdomains: list) -> list:
    """
    Identify potential admin/panel interfaces from subdomains.
    """
    admin_keywords = [
        "admin", "panel", "portal", "manager", "manage", "operator", 
        "control", "config", "settings", "setup", "dashboard", "cpanel",
        "webmail", "whm", "plesk", "directadmin", "neibu"
    ]
    
    admin_interfaces = []
    for subdomain in subdomains:
        for keyword in admin_keywords:
            if keyword in subdomain.lower():
                admin_interfaces.append({
                    "subdomain": subdomain,
                    "type": keyword,
                    "confidence": "high" if keyword in ["admin", "panel", "neibu"] else "medium"
                })
                break  # Avoid duplicates
                
    return admin_interfaces


def identify_internal_infrastructure(subdomains: list) -> dict:
    """
    Identify internal infrastructure patterns from subdomains.
    """
    internal_patterns = {
        "kyc": [],
        "internal": [],
        "private": [],
        "dev": [],
        "staging": [],
        "test": [],
        "neibu": [],  # Chinese admin panel tell
        "other": []
    }
    
    for subdomain in subdomains:
        sub_lower = subdomain.lower()
        if "kyc" in sub_lower:
            internal_patterns["kyc"].append(subdomain)
        elif "internal" in sub_lower:
            internal_patterns["internal"].append(subdomain)
        elif "private" in sub_lower:
            internal_patterns["private"].append(subdomain)
        elif any(dev_kw in sub_lower for dev_kw in ["dev", "development"]):
            internal_patterns["dev"].append(subdomain)
        elif "staging" in sub_lower:
            internal_patterns["staging"].append(subdomain)
        elif "test" in sub_lower:
            internal_patterns["test"].append(subdomain)
        elif "neibu" in sub_lower:
            internal_patterns["neibu"].append(subdomain)
        else:
            internal_patterns["other"].append(subdomain)
    
    return internal_patterns


# Map a social/content host to a human label. A link only counts when it points at a
# *profile/path* on the platform (e.g. t.me/<channel>), not just the bare homepage.
_SOCIAL_HOSTS = {
    "facebook.com": "Facebook", "fb.com": "Facebook", "twitter.com": "X/Twitter",
    "x.com": "X/Twitter", "instagram.com": "Instagram", "linkedin.com": "LinkedIn",
    "youtube.com": "YouTube", "youtu.be": "YouTube", "tiktok.com": "TikTok",
    "t.me": "Telegram", "telegram.me": "Telegram", "wa.me": "WhatsApp",
    "discord.gg": "Discord", "discord.com": "Discord", "reddit.com": "Reddit",
    "pinterest.com": "Pinterest", "vk.com": "VKontakte", "weibo.com": "Weibo",
    "medium.com": "Medium", "github.com": "GitHub",
}
_SOCIAL_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


async def _extract_social_links(client, domain: str) -> list:
    """Fetch a domain's homepage and return the *real* outbound social-media profile
    links it embeds. This is genuine signal (operator Telegram channels, support chats,
    brand pages) — unlike substring-matching platform names against the domain itself."""
    links = []
    try:
        r = await client.get(f"https://{domain}", timeout=8.0, follow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (compatible; CRUCIBLE-SIGINT/5.1)"})
        if r.status_code not in (200, 206):
            return links
        seen = set()
        for href in _SOCIAL_HREF_RE.findall(r.text[:200000]):
            low = href.lower()
            for host, label in _SOCIAL_HOSTS.items():
                # Must be a link TO the platform with a path (a profile), not the seed
                # domain merely containing the platform name.
                if (f"//{host}/" in low or f".{host}/" in low or low.startswith(host + "/")):
                    path = low.split(host, 1)[1].lstrip("/")
                    if not path or path.startswith(("share", "sharer", "intent", "home")):
                        continue  # share buttons / homepages aren't a real presence
                    key = (host, path.split("?")[0].rstrip("/"))
                    if key in seen:
                        continue
                    seen.add(key)
                    links.append({"domain": domain, "platform": label,
                                  "url": href if href.startswith("http") else f"https://{host}/{path}"})
    except Exception:
        pass
    return links[:8]


async def check_social_media_presence(domains: list) -> dict:
    """
    Find REAL social-media presence by fetching a bounded sample of the discovered
    domains' homepages and extracting the social profile links they actually embed.
    (The previous implementation substring-matched platform names like "x" against the
    domain text, which matched almost everything and produced false signals.)
    """
    domain_names = [d.get("name", "") for d in domains
                    if d.get("name") and "." in d.get("name", "")]
    # Bound the active fetches — homepage of the seed + a sample of the cluster.
    sample = domain_names[:8]
    social_media_matches = []
    if sample:
        sem = asyncio.Semaphore(6)
        async with httpx.AsyncClient() as client:
            async def _one(dom):
                async with sem:
                    return await _extract_social_links(client, dom)
            for links in await asyncio.gather(*[_one(d) for d in sample]):
                social_media_matches.extend(links)

    # Suspicious lexical markers in the discovered domain names (kept — this is a real
    # cheap signal, unlike the old platform substring matching).
    suspicious_patterns = [
        {"domain": d, "pattern": "fake/scam indicator", "type": "suspicious"}
        for d in domain_names
        if any(p in d.lower() for p in ("fake", "scam", "fraud", "phish", "verify", "support-"))
    ]

    platforms_found = sorted({m["platform"] for m in social_media_matches})
    social_score = min(100, len(social_media_matches) * 12 + len(suspicious_patterns) * 8)

    return {
        "social_media_matches": social_media_matches,
        "content_platform_matches": [],  # superseded by real link extraction above
        "suspicious_patterns": suspicious_patterns,
        "platforms_found": platforms_found,
        "domains_scanned": len(sample),
        "social_platform_score": social_score,
        "total_matches": len(social_media_matches),
        "analysis_complete": True,
    }


def map_content_similarity(domains: list) -> dict:
    """
    Map content similarity across platforms by analyzing domain naming patterns.
    
    Args:
        domains: List of discovered domains
        
    Returns:
        dict: Content similarity mapping results
    """
    # Extract domain names
    domain_names = [d.get("name", "") for d in domains if d.get("name")]
    
    # Group domains by content similarity patterns
    similarity_groups = {}
    
    # Common scam naming patterns
    scam_patterns = [
        "wealth", "invest", "profit", "fxtrad", "bitco", "ethereum", "crypt",
        "trader", "broker", "market", "vip", "promo", "limited", "secure",
        "account", "login", "wallet", "connect", "app", "portal", "dashboard"
    ]
    
    # Check each domain for similarity patterns
    for domain in domain_names:
        # Extract base name without TLD
        base_name = domain.split(".")[0].lower()
        
        # Check for scam patterns
        found_patterns = [pattern for pattern in scam_patterns if pattern in base_name]
        
        # Group by patterns
        for pattern in found_patterns:
            if pattern not in similarity_groups:
                similarity_groups[pattern] = []
            similarity_groups[pattern].append(domain)
    
    # Calculate similarity score
    similarity_score = 0
    if similarity_groups:
        # Score based on number of groups and size of groups
        group_count = len(similarity_groups)
        max_group_size = max(len(domains) for domains in similarity_groups.values()) if similarity_groups else 0
        similarity_score = min(100, (group_count * 10) + (max_group_size * 5))
    
    return {
        "similarity_groups": similarity_groups,
        "scam_patterns": scam_patterns,
        "content_similarity_score": similarity_score,
        "analysis_complete": True
    }


def correlate_ip_neighbors(ip_results: list, reverse_ip_data: list) -> dict:
    """
    Correlate IP neighbors to map hosting provider networks and identify shared infrastructure patterns.
    """
    # Extract all IPs and their associated domains
    ip_domains = {}
    for data in reverse_ip_data:
        if "domains" in data:
            ip_domains[data["ip"]] = data["domains"]
    
    return ip_domains


def identify_shared_infrastructure(ip_domains: dict) -> dict:
    """
    Identify shared infrastructure patterns across different scam operations
    by analyzing domain overlaps and common hosting providers.
    """
    shared_patterns = {
        "common_ips": [],
        "shared_hosting": {},
        "infrastructure_clusters": [],
        "suspicious_patterns": []
    }
    
    # Count how many domains are hosted on each IP
    ip_domain_count = {}
    for ip, domains in ip_domains.items():
        ip_domain_count[ip] = len(domains)
    
    # Identify IPs hosting many domains (potential shared hosting)
    common_ips = [ip for ip, count in ip_domain_count.items() if count > 5]
    shared_patterns["common_ips"] = common_ips
    
    # Identify infrastructure clusters (groups of domains on same IPs)
    clusters = []
    for ip, domains in ip_domains.items():
        if len(domains) > 3:
            clusters.append({
                "ip": ip,
                "domains": domains,
                "count": len(domains)
            })
    shared_patterns["infrastructure_clusters"] = clusters
    
    # Flag suspicious patterns
    if common_ips:
        shared_patterns["suspicious_patterns"].append(f"Found {len(common_ips)} IPs hosting multiple domains - potential shared infrastructure")

    return shared_patterns


# ────────────────────────────────────────────────────────────────────
# abuse.ch ThreatFox — sister-domain / co-hosted-IOC lookup
#
# The existing IOC-correlation engine queries URLHaus exactly for the seed,
# which misses ThreatFox listings entirely and also misses *.seed sister
# domains co-hosted on the same infrastructure. ThreatFox's `search_ioc`
# query does substring matching on the value field, so:
#   - search_term=<seed-domain>  surfaces *.seed listings
#   - search_term=<resolved-ip>  surfaces sister IOCs hosted on that IP
# Together those two queries cover the gap the user flagged
# (e.g. *.bet30bet.com entries that don't appear when you only look up
# bet30bet.com exactly in URLHaus).
# ────────────────────────────────────────────────────────────────────

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

async def _threatfox_search(client: httpx.AsyncClient, term: str, api_key: str) -> List[Dict[str, Any]]:
    """One `search_ioc` POST to ThreatFox. Returns the raw IOC list (or [])."""
    if not term:
        return []
    headers = {"Accept": "application/json"}
    if api_key:
        # abuse.ch unified Auth-Key — works across ThreatFox / URLHaus /
        # MalwareBazaar. Without it, recent ThreatFox versions return 401.
        headers["Auth-Key"] = api_key
    payload = {"query": "search_ioc", "search_term": term}
    try:
        r = await client.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=15.0)
        if r.status_code != 200:
            return [{"_error": f"ThreatFox HTTP {r.status_code}", "_term": term}]
        data = r.json()
        if data.get("query_status") == "ok":
            return data.get("data", []) or []
        if data.get("query_status") == "no_result":
            return []
        return [{"_error": f"ThreatFox: {data.get('query_status','unknown')}", "_term": term}]
    except Exception as e:
        return [{"_error": f"ThreatFox query failed: {e}", "_term": term}]


async def fetch_threatfox(seed, ips: List[str], api_key: str = "") -> Dict[str, Any]:
    """Query ThreatFox for the seed term(s) and each resolved IP, dedupe results.

    `seed` can be a single string (back-compat) or a list of strings. When a
    list is supplied, every term is queried — useful for pivoting between the
    exact seed (e.g. liizlfb.bet30bet.com) and its registrable domain
    (bet30bet.com), since ThreatFox `search_ioc` does substring matching on
    the IOC value field. Without the registrable-domain query, sister
    subdomains under the same brand are missed.

    Returns a dict with:
      matches: list of normalized IOCs (sorted, most-recent first)
      queried: list of {term, kind, count} per query for transparency
      seed_hits / ip_hits: counts split by which query surfaced the IOC
      error: present only on a hard failure (no successful query)
    """
    queried = []
    matches: Dict[str, Dict[str, Any]] = {}
    terms = []
    # Normalize seed input — accept either a string or a list of strings.
    seed_iter = [seed] if isinstance(seed, str) else (list(seed) if seed else [])
    seen_seed = set()
    for s in seed_iter:
        if s and s not in seen_seed:
            seen_seed.add(s)
            terms.append(("seed", s))
    # Cap to a sensible number of IPs — analyst can re-run if needed
    for ip in (ips or [])[:8]:
        if ip:
            terms.append(("ip", ip))

    if not terms:
        return {"matches": [], "queried": [], "seed_hits": 0, "ip_hits": 0}

    hard_errors = []
    try:
        async with httpx.AsyncClient() as client:
            # Fan out — sequential calls add up to >15s for 9 terms. ThreatFox
            # handles concurrent requests fine and we cap term count above.
            results = await asyncio.gather(
                *[_threatfox_search(client, term, api_key) for _, term in terms],
                return_exceptions=False,
            )
            for (kind, term), rows in zip(terms, results):
                err = next((r["_error"] for r in rows if isinstance(r, dict) and "_error" in r), None)
                if err:
                    hard_errors.append({"term": term, "error": err})
                    queried.append({"term": term, "kind": kind, "count": 0, "error": err})
                    continue
                queried.append({"term": term, "kind": kind, "count": len(rows)})
                for row in rows:
                    if not isinstance(row, dict) or "_error" in row:
                        continue
                    # Dedupe on (ioc_value, ioc_type)
                    key = f"{row.get('ioc_type','')}::{row.get('ioc','')}"
                    if key not in matches:
                        first_n = _normalize_ts(row.get("first_seen"))
                        last_n  = _normalize_ts(row.get("last_seen")) or first_n
                        matches[key] = {
                            "ioc": row.get("ioc"),
                            "ioc_type": row.get("ioc_type"),
                            "threat_type": row.get("threat_type"),
                            "malware": row.get("malware_printable") or row.get("malware") or "",
                            "malware_alias": row.get("malware_alias") or "",
                            "confidence": row.get("confidence_level"),
                            "first_seen": first_n,
                            "last_seen": last_n,
                            "reporter": row.get("reporter"),
                            "tags": row.get("tags") or [],
                            "reference": row.get("reference"),
                            "matched_by": set(),
                        }
                    matches[key]["matched_by"].add(kind)
    except Exception as e:
        return {"matches": [], "queried": queried, "seed_hits": 0, "ip_hits": 0,
                "error": f"ThreatFox bulk query failed: {e}"}

    out_list = []
    for v in matches.values():
        v["matched_by"] = sorted(v["matched_by"])
        out_list.append(v)
    # Most recent first; missing dates sort last
    out_list.sort(key=lambda r: (r.get("last_seen") or r.get("first_seen") or ""), reverse=True)

    result = {
        "matches": out_list,
        "queried": queried,
        "seed_hits": sum(1 for r in out_list if "seed" in r["matched_by"]),
        "ip_hits": sum(1 for r in out_list if "ip" in r["matched_by"]),
    }
    if hard_errors and not out_list:
        # Surface the error only if we got nothing useful — partial errors are noise
        result["error"] = hard_errors[0]["error"]
    return result


# ────────────────────────────────────────────────────────────────────
# AlienVault OTX — IP passive-DNS sister-domain lookup
#
# The existing OTX query only looks at /indicators/domain/<seed>/general,
# which surfaces pulse memberships for the seed itself. /indicators/ip/<ip>/
# passive_dns returns every domain OTX has observed on that IP — which is
# the natural sister-domain pivot once we know the seed's current IPs.
# ────────────────────────────────────────────────────────────────────

async def fetch_otx_ip_passive_dns(ips: List[str], api_key: str = "", per_ip_cap: int = 200) -> Dict[str, Any]:
    """For each IP, pull OTX passive-DNS sister domains.

    Returns:
      per_ip: list of {ip, domains:[{hostname,first,last}], count, error?}
      flat:   deduped union across IPs, each domain tagged with the IPs that saw it
    """
    if not api_key:
        return {"error": "AlienVault OTX API key not configured", "per_ip": [], "flat": []}
    if not ips:
        return {"per_ip": [], "flat": []}

    per_ip = []
    flat: Dict[str, Dict[str, Any]] = {}

    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}

    async def _query_one(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        kind = "IPv6" if ":" in ip else "IPv4"
        url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/passive_dns"
        try:
            r = await client.get(url, headers=headers, timeout=15.0)
            if r.status_code != 200:
                return {"ip": ip, "domains": [], "count": 0,
                        "error": f"OTX HTTP {r.status_code}"}
            data = r.json()
            rows = data.get("passive_dns", []) or []
            # Normalise per-row timestamps before sorting so mixed-type values
            # (some OTX entries have ints) don't TypeError on comparison.
            for row in rows:
                row["first"] = _normalize_ts(row.get("first"))
                row["last"]  = _normalize_ts(row.get("last"))
            rows.sort(key=lambda x: x.get("last") or x.get("first") or "", reverse=True)
            rows = rows[:per_ip_cap]
            doms = []
            for row in rows:
                host = (row.get("hostname") or "").lower().strip(".")
                if not host:
                    continue
                doms.append({
                    "hostname": host,
                    "first": row.get("first"),
                    "last": row.get("last"),
                    "record_type": row.get("record_type"),
                })
            return {"ip": ip, "domains": doms, "count": len(doms)}
        except Exception as e:
            return {"ip": ip, "domains": [], "count": 0, "error": f"OTX query failed: {e}"}

    try:
        async with httpx.AsyncClient() as client:
            # Fan out per-IP queries concurrently — was ~1s × 8 IPs sequentially,
            # now ~1s total. Bounded above to 8 IPs.
            per_ip = await asyncio.gather(*[_query_one(client, ip) for ip in ips[:8]])
        # Aggregate after the gather so the flat dict isn't a contention hazard
        for entry in per_ip:
            for row in entry.get("domains", []):
                host = row["hostname"]
                agg = flat.setdefault(host, {"hostname": host, "ips": set(),
                                             "first": row.get("first"), "last": row.get("last")})
                agg["ips"].add(entry["ip"])
                f, l = row.get("first"), row.get("last")
                if f and (not agg["first"] or f < agg["first"]):
                    agg["first"] = f
                if l and (not agg["last"] or l > agg["last"]):
                    agg["last"] = l
    except Exception as e:
        return {"error": f"OTX bulk query failed: {e}", "per_ip": per_ip, "flat": []}

    flat_list = []
    for v in flat.values():
        v["ips"] = sorted(v["ips"])
        flat_list.append(v)
    # Sort: most IPs first (broadest co-hosting evidence), then most recent.
    # OTX timestamps are ISO-8601 strings, so a plain reverse string sort
    # ranks newer first when dates share the same prefix.
    flat_list.sort(key=lambda r: (-len(r["ips"]), -(_iso_to_int(r.get("last") or r.get("first") or ""))))

    return {"per_ip": per_ip, "flat": flat_list}


def _iso_to_int(s: str) -> int:
    """Turn an ISO-8601 timestamp into a comparable integer (or 0).
    Falls back to 0 on any parse mismatch — used purely for sort ordering."""
    if not s:
        return 0
    digits = "".join(c for c in s if c.isdigit())[:14]
    return int(digits) if digits else 0


# ────────────────────────────────────────────────────────────────────
# OTX domain → passive-DNS — historical A/AAAA observations with timestamps.
# Complements fetch_otx_ip_passive_dns (IP→hostnames); this is the inverse
# and is what powers the HOSTING IP HISTORY panel's "LAST HOSTED" labels for
# IPs that VirusTotal doesn't carry a `last_resolved` for.
# ────────────────────────────────────────────────────────────────────

async def fetch_otx_domain_passive_dns(
    domain: str, api_key: str = "", cap: int = 500,
) -> Dict[str, Any]:
    """Historical A/AAAA records for `domain` from OTX.

    Returns:
      domain: echoed
      records: list of {ip, first, last, record_type, hostname} — sorted
               most-recent-first
      count: len(records) after capping
    Empty list (no error) when OTX has no observations.
    """
    if not api_key:
        return {"error": "AlienVault OTX API key not configured",
                "domain": domain, "records": [], "count": 0}

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=headers)
        if r.status_code != 200:
            return {"error": f"OTX HTTP {r.status_code}",
                    "domain": domain, "records": [], "count": 0}
        data = r.json() or {}
        rows = data.get("passive_dns") or []
        # OTX returns both forward and reverse observations; keep A / AAAA only.
        cleaned: list = []
        for row in rows:
            rtype = (row.get("record_type") or "").upper()
            if rtype not in ("A", "AAAA"):
                continue
            ip = (row.get("address") or "").strip()
            if not ip or not _is_ip(ip):
                continue
            first_n = _normalize_ts(row.get("first"))
            last_n  = _normalize_ts(row.get("last")) or first_n
            cleaned.append({
                "ip": ip,
                "first": first_n,
                "last": last_n,
                "record_type": rtype,
                "hostname": (row.get("hostname") or domain).lower(),
            })
        cleaned.sort(key=lambda x: x["last"] or x["first"] or "", reverse=True)
        cleaned = cleaned[:cap]
        return {"domain": domain, "records": cleaned, "count": len(cleaned)}
    except Exception as e:
        return {"error": f"OTX domain passive-DNS failed: {e}",
                "domain": domain, "records": [], "count": 0}


# ────────────────────────────────────────────────────────────────────
# OTX pulse / general lookup — surfaces malware-family + tag attribution
# (the existing passive-DNS call returns hostnames only).
# ────────────────────────────────────────────────────────────────────

async def fetch_otx_general(seeds, api_key: str = "", per_seed_cap: int = 30) -> Dict[str, Any]:
    """Pull OTX general/pulse info for one or more seeds (domains or IPs).

    Returns:
      per_seed: list of {seed, kind, pulses:[{id, name, tags, malware_families,
                attack_ids, author_name, created, modified, ...}],
                pulse_count, error?}

    Pulses are sorted recent-first and capped at per_seed_cap to bound noise
    (a single seed can sit in hundreds of low-signal pulses).
    """
    if not api_key:
        return {"error": "AlienVault OTX API key not configured", "per_seed": []}
    if isinstance(seeds, str):
        seeds = [seeds]
    seeds = [s for s in (seeds or []) if s]
    if not seeds:
        return {"per_seed": []}

    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}

    async def _query_one(client: httpx.AsyncClient, seed: str) -> Dict[str, Any]:
        if _is_ip(seed):
            kind = "IPv6" if ":" in seed else "IPv4"
        else:
            kind = "domain"
        url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{seed}/general"
        try:
            r = await client.get(url, headers=headers, timeout=15.0)
            if r.status_code != 200:
                return {"seed": seed, "kind": kind, "pulses": [],
                        "pulse_count": 0, "error": f"OTX HTTP {r.status_code}"}
            data = r.json() or {}
            pulse_info = data.get("pulse_info") or {}
            pulses = pulse_info.get("pulses") or []
            for p in pulses:
                p["created"]  = _normalize_ts(p.get("created"))
                p["modified"] = _normalize_ts(p.get("modified"))
            pulses.sort(key=lambda p: (p.get("modified") or p.get("created") or ""),
                        reverse=True)
            trimmed = []
            for p in pulses[:per_seed_cap]:
                trimmed.append({
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": (p.get("description") or "")[:300],
                    "tags": p.get("tags") or [],
                    "malware_families": p.get("malware_families") or [],
                    "attack_ids": p.get("attack_ids") or [],
                    "author_name": p.get("author_name"),
                    "created": p.get("created"),
                    "modified": p.get("modified"),
                    "tlp": p.get("TLP") or p.get("tlp"),
                })
            return {"seed": seed, "kind": kind, "pulses": trimmed,
                    "pulse_count": pulse_info.get("count") or len(trimmed)}
        except Exception as e:
            return {"seed": seed, "kind": kind, "pulses": [], "pulse_count": 0,
                    "error": f"OTX general query failed: {e}"}

    try:
        async with httpx.AsyncClient() as client:
            per_seed = await asyncio.gather(
                *[_query_one(client, s) for s in seeds[:8]],
            )
    except Exception as e:
        return {"error": f"OTX general bulk failed: {e}", "per_seed": []}

    return {"per_seed": per_seed}


# ────────────────────────────────────────────────────────────────────
# IP → hosted-domains → ThreatFox + OTX enrichment
# ────────────────────────────────────────────────────────────────────

async def fetch_ip_hosted_domains_intel(
    ip: str,
    *,
    abusech_key: str = "",
    otx_key: str = "",
    max_domains: int = 15,
) -> dict:
    """
    Threat-intel sweep over every domain hosted by `ip`.

    Pipeline:
      1. Reverse-IP lookup (HackerTarget) — currently-resolving domains.
      2. OTX passive DNS for `ip` — historically-observed hostnames.
         Skipped silently if otx_key is empty.
      3. Union both sets, cap at `max_domains` to keep ThreatFox fan-out sane.
      4. ThreatFox bulk query — each domain as a search term, plus the IP itself.

    Returns per-source raw results plus an aggregated `hosted_domains` list
    with provenance per domain (which source surfaced it) and the ThreatFox
    match set keyed by IOC.
    """
    if not _is_ip(ip):
        return {"error": f"Not a valid IP: {ip}"}

    tasks = [fetch_reverse_ip_lookup(ip)]
    if otx_key:
        tasks.append(fetch_otx_ip_passive_dns([ip], otx_key))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    reverse_data = results[0]
    if isinstance(reverse_data, Exception):
        reverse_data = {"error": f"Reverse-IP failed: {reverse_data}",
                        "domains": [], "count": 0}
    otx_data: Dict[str, Any]
    if otx_key:
        otx_data = results[1]
        if isinstance(otx_data, Exception):
            otx_data = {"error": f"OTX failed: {otx_data}",
                        "per_ip": [], "flat": []}
    else:
        otx_data = {"per_ip": [], "flat": [],
                    "note": "OTX skipped — no AlienVault key configured"}

    rev_domains = {d.lower() for d in (reverse_data.get("domains") or [])}
    otx_domains: set = set()
    for entry in (otx_data.get("per_ip") or []):
        for row in entry.get("domains", []):
            h = (row.get("hostname") or "").lower().strip(".")
            if h:
                otx_domains.add(h)

    union = sorted(rev_domains | otx_domains)
    capped = union[:max_domains]

    evidence: dict = {}
    for d in rev_domains: evidence.setdefault(d, []).append("reverse-ip")
    for d in otx_domains: evidence.setdefault(d, []).append("otx-passive-dns")

    threatfox_data = await fetch_threatfox(capped, [ip], abusech_key)

    return {
        "ip": ip,
        "hosted_domains": [
            {"domain": d, "evidence": sorted(set(evidence.get(d, [])))}
            for d in union
        ],
        "hosted_domain_count": len(union),
        "queried_for_threatfox": capped,
        "queried_count": len(capped),
        "truncated": len(union) > max_domains,
        "reverse_ip": reverse_data,
        "otx_passive_dns": otx_data,
        "threatfox": threatfox_data,
        "otx_enabled": bool(otx_key),
        "threatfox_enabled": bool(abusech_key),
    }


# ────────────────────────────────────────────────────────────────────
# Google Threat Intelligence (GTI) — formerly Mandiant Advantage TI
# ────────────────────────────────────────────────────────────────────

async def fetch_gti_intel(seed: str, api_key: str) -> dict:
    """
    Pull Google Threat Intelligence data for a domain or IP.

    GTI is the rebranded Mandiant + VirusTotal Enterprise tier; endpoints share
    the /api/v3 path with regular VT, but the API key needs GTI entitlement —
    the relationship fields (`collections`, `related_threat_actors`,
    `associated_malware`, `campaigns`, `related_attack_techniques`) only
    populate when the key carries that entitlement.

    Behaviour by key tier:
      * No key            → returns {"error": ...}
      * VT-only key       → returns basic attributes; `gti_enabled` is False,
                            relationship lists are empty.
      * GTI-entitled key  → relationships populate; Mandiant attribution and
                            gti_assessment surface under their own fields.
    """
    if not api_key:
        return {"error": "GTI/VirusTotal API key not configured",
                "gti_enabled": False}

    seed_is_ip = _is_ip(seed)
    base = "ip_addresses" if seed_is_ip else "domains"
    base_url = f"https://www.virustotal.com/api/v3/{base}/{seed}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    # Relationship names to probe individually. Each gets its own HTTP call so a
    # 400/404 on one (because the name isn't valid on this object type, or the
    # key has no entitlement for it) doesn't tank the others. Anything that
    # returns non-200 is silently skipped.
    rel_names = [
        "related_threat_actors", "associated_threat_actors",
        "collections", "associated_collections",
        "associated_malware", "malware_families",
        "campaigns", "associated_campaigns",
        "attack_techniques", "related_attack_techniques",
        "related_references",
    ]

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(base_url, headers=headers)
            if r.status_code == 401:
                return {"error": "GTI/VT key unauthorized (HTTP 401)",
                        "gti_enabled": False}
            if r.status_code == 404:
                return {"seed": seed, "found": False, "gti_enabled": False,
                        "note": "Seed not present in GTI/VT corpus"}
            if r.status_code != 200:
                try:
                    body = r.json()
                    msg = (((body or {}).get("error") or {}).get("message")
                           or str(body)[:200])
                except Exception:
                    msg = (r.text or "")[:200]
                return {"error": f"GTI HTTP {r.status_code}: {msg}",
                        "gti_enabled": False}

            data = (r.json() or {}).get("data", {}) or {}
            attrs = data.get("attributes", {}) or {}

            async def _enrich_via_collections(obj_id: str) -> dict:
                """Mandiant threat actors / malware / campaigns surface as
                `collection` objects in GTI. When the relationship endpoint
                gives only descriptors, this resolves the human-readable name
                and description by hitting /api/v3/collections/{id}."""
                try:
                    cr = await client.get(
                        f"https://www.virustotal.com/api/v3/collections/{obj_id}",
                        headers=headers,
                    )
                    if cr.status_code != 200:
                        return {}
                    cia = ((cr.json() or {}).get("data") or {}).get("attributes") or {}
                    return {
                        "name": (cia.get("name") or cia.get("display_name")
                                 or cia.get("value") or ""),
                        "description": (cia.get("description") or "")[:400],
                        "collection_type": cia.get("collection_type") or "",
                        "tags": cia.get("tags") or [],
                    }
                except Exception:
                    return {}

            async def _fetch_rel(name: str) -> tuple[str, list]:
                try:
                    # `/{name}` is the SHORTCUT endpoint — returns full related
                    # objects with attributes. `/relationships/{name}` returns
                    # descriptors only (id+type) which is why earlier output
                    # showed raw STIX IDs like `threat-actor--<uuid>` instead
                    # of "UNC6861". When the shortcut isn't available we fall
                    # through to per-id enrichment via /collections/{id}.
                    rr = await client.get(
                        f"{base_url}/{name}?limit=20",
                        headers=headers,
                    )
                    if rr.status_code != 200:
                        return (name, [])
                    items = (rr.json() or {}).get("data") or []
                    refs = []
                    enrich_tasks = []
                    enrich_indices = []
                    for idx, i in enumerate(items):
                        ia = i.get("attributes") or {}
                        ref = {
                            "id": i.get("id"),
                            "type": i.get("type"),
                            "name": (ia.get("name") or ia.get("display_name")
                                     or ia.get("value") or ""),
                            "description": (ia.get("description") or "")[:400],
                        }
                        if not ref["name"] and ref["id"]:
                            enrich_tasks.append(_enrich_via_collections(ref["id"]))
                            enrich_indices.append(idx)
                        refs.append(ref)
                    if enrich_tasks:
                        enriched = await asyncio.gather(*enrich_tasks)
                        for idx, e in zip(enrich_indices, enriched):
                            if e.get("name"):
                                refs[idx]["name"] = e["name"]
                            if e.get("description") and not refs[idx]["description"]:
                                refs[idx]["description"] = e["description"]
                            if e.get("collection_type"):
                                refs[idx]["collection_type"] = e["collection_type"]
                    # Last resort: if still no name, use the id (so the log
                    # line at least has an identifier).
                    for ref in refs:
                        if not ref["name"]:
                            ref["name"] = ref["id"] or "?"
                    return (name, refs)
                except Exception:
                    return (name, [])

            rel_results = await asyncio.gather(
                *[_fetch_rel(n) for n in rel_names]
            )

        rels = {name: refs for name, refs in rel_results}

        # Coalesce aliases that point at the same data on different object types.
        threat_actors = rels.get("related_threat_actors") or rels.get("associated_threat_actors") or []
        collections   = rels.get("collections") or rels.get("associated_collections") or []
        malware       = rels.get("associated_malware") or rels.get("malware_families") or []
        campaigns     = rels.get("campaigns") or rels.get("associated_campaigns") or []
        attack_tech   = rels.get("attack_techniques") or rels.get("related_attack_techniques") or []
        references    = rels.get("related_references") or []

        # Mandiant/GTI attribute survey — accept both `mandiant_*` and `gti_*`
        # key prefixes, since GTI uses a mix.
        mandiant_attrs = {
            k: v for k, v in attrs.items()
            if k.startswith("mandiant_") or k.startswith("gti_")
        }
        gti_assessment = (
            attrs.get("gti_assessment")
            or attrs.get("crowdsourced_context")
            or None
        )

        last_analysis_stats = attrs.get("last_analysis_stats") or {}
        malicious_count = int(last_analysis_stats.get("malicious", 0) or 0)
        total_count = sum(int(v or 0) for v in last_analysis_stats.values())

        # Permissive entitlement detection: any GTI-tier or Mandiant signal.
        gti_enabled = bool(
            threat_actors or collections or malware or campaigns or attack_tech
            or mandiant_attrs or gti_assessment
        )

        gui_path = "ip-address" if seed_is_ip else "domain"

        return {
            "seed": seed,
            "seed_kind": "ip" if seed_is_ip else "domain",
            "found": True,
            "gti_enabled": gti_enabled,
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": last_analysis_stats,
            "malicious_vendor_count": malicious_count,
            "total_vendor_count": total_count,
            "categories": attrs.get("categories") or {},
            "tags": attrs.get("tags") or [],
            "last_dns_records": attrs.get("last_dns_records") or [],
            "creation_date": attrs.get("creation_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "popularity_ranks": attrs.get("popularity_ranks") or {},
            "registrar": attrs.get("registrar"),
            "whois": (attrs.get("whois") or "")[:600],
            "gti_assessment": gti_assessment,
            "mandiant_attribution": mandiant_attrs,
            "collections": collections,
            "threat_actors": threat_actors,
            "malware_families": malware,
            "campaigns": campaigns,
            "attack_techniques": attack_tech,
            "related_references": references,
            "permalink": f"https://www.virustotal.com/gui/{gui_path}/{seed}",
        }
    except Exception as e:
        return {"error": f"GTI fetch failed: {e}", "gti_enabled": False}
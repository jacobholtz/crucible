"""
CRUCIBLE SIGINT v5.1
====================
Passive OSINT infrastructure fingerprinting engine.

METHODOLOGY CREDIT
------------------
The foundational analytical approach in CRUCIBLE is directly inspired by the
investigation published by Ryan McDonald (Principal Security Engineer, USMC 0341)
documenting his passive pivot of the DSJ Exchange / BG Wealth Sharing pig-butchering
operation — a $150M cryptocurrency fraud ultimately traced by FBI Operation Level Up.

Ryan's article: "Fingerprinting Malicious Infrastructure Using Free Resources"
Published: LinkedIn, May 2026

Ryan demonstrated — using only free passive sources (crt.sh, urlscan.io, DNS, WHOIS,
manual JS inspection) — how a single confirmed-bad domain can be used to map an entire
criminal infrastructure cluster. CRUCIBLE automates that methodology into a
repeatable multi-stage discovery and pivot pipeline.

All credit for the investigative framework belongs to Ryan McDonald.
CRUCIBLE is the automation layer built on top of his published work.

AUTHOR
------
Randy Bator | Security 360, LLC DBA NEATLABS™
rbator@neatlabs.ai | https://neatlabs.ai
LinkedIn: linkedin.com/in/randy-b-84aa6731

LICENSE
-------
MIT License — see LICENSE file

USAGE
-----
pip install fastapi uvicorn httpx
python crucible_app.py
Open: http://localhost:8000
"""

import asyncio
import json
import os
import re
import ipaddress
import pathlib
import subprocess
import sys
import time
from urllib.parse import quote
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager
from collections import Counter

# Local modules
from infrastructure_timeline import fetch_infrastructure_timeline, get_migration_patterns

import httpx
from fastapi import FastAPI, Query, Body
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
import uvicorn
import publicsuffix2

BASE_DIR = pathlib.Path(__file__).parent.resolve()
TEMPLATE = BASE_DIR / "templates" / "index.html"

# Module-level constant — ASN numbers known to belong to datacenter/hosting providers.
# Rebuilt here once rather than inside the hot path of fetch_ipinfo().
DATACENTER_ASNS: frozenset[int] = frozenset({
    # Major cloud / CDN
    15169, 16509, 14618, 13335, 8075, 20940, 16591, 54113,
    396982, 19527, 36459, 32934, 63949, 14061, 22822,
    # Chinese cloud providers
    4134, 4837, 9808, 4538,
    # VPS / shared hosting frequently used in scam ops
    47583,  # Hostinger
    24940,  # Hetzner
    16276,  # OVH
    51167,  # Contabo
    9009,   # M247
    20473,  # Vultr
})

client: Optional[httpx.AsyncClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global client
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "CRUCIBLE-SIGINT/5.0 (OSINT Research Tool)"},
        limits=httpx.Limits(max_connections=30, max_keepalive_connections=15),
    )
    yield
    await client.aclose()

app = FastAPI(title="CRUCIBLE SIGINT", version="5.1", lifespan=lifespan)

# ════════════════════════════════════════════════════════════
# VALIDATION
# ════════════════════════════════════════════════════════════

DOMAIN_RE = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')

# ════════════════════════════════════════════════════════════
# GLOBAL CONFIG
# ════════════════════════════════════════════════════════════

# API Keys - Set these as environment variables for security
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_API_KEY = os.environ.get("ALIENVAULT_API_KEY", "")
CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
# Certspotter works free/unauthenticated but with low rate limits; a key raises them.
CERTSPOTTER_API_KEY = os.environ.get("CERTSPOTTER_API_KEY", "")
# Unified abuse.ch Auth-Key — used across ThreatFox / URLHaus / MalwareBazaar.
# Current ThreatFox v1 returns 401 without it for the search_ioc query.
ABUSECH_API_KEY = os.environ.get("ABUSECH_API_KEY", "")
# CIRCL.lu Passive DNS — HTTP Basic auth via username + password.
CIRCL_PDNS_USERNAME = os.environ.get("CIRCL_PDNS_USERNAME", "")
CIRCL_PDNS_PASSWORD = os.environ.get("CIRCL_PDNS_PASSWORD", "")
# Mnemonic Argus Passive DNS — Argus-API-Key header.
MNEMONIC_API_KEY = os.environ.get("MNEMONIC_API_KEY", "")
# Google Threat Intelligence (formerly Mandiant Advantage) shares the
# /api/v3 surface with VirusTotal — GTI entitlement rides on the same key.
# Whether the relationship fields populate is determined per response by the
# fetcher, not by a separate key.

# Pluggable certificate-transparency providers (scantower.io, Cloudflare, or any
# HTTP-JSON CT API). Their public query contracts aren't verified here, so each is
# fully configurable: an API key + a URL template containing {q} (the domain/brand).
# The generic fetcher GETs the URL and extracts domain-like strings from the JSON. A
# provider is only attempted when BOTH its key and URL are set (in env or Settings).
# (certkit.io is a verified first-class source — see _ct_certkit — not a generic one.)
CT_PROVIDERS = {
    "scantower":  {"label": "scantower.io",     "key": os.environ.get("SCANTOWER_API_KEY", ""),   "url": os.environ.get("SCANTOWER_CT_URL", "")},
    "cloudflare": {"label": "Cloudflare Radar", "key": os.environ.get("CLOUDFLARE_API_TOKEN", ""),"url": os.environ.get("CLOUDFLARE_CT_URL", "")},
}

# Master switch for the automated revalidation feature (Settings tab toggle).
# When False, the revalidation endpoints that perform active monitoring refuse
# to run; read-only report/status endpoints stay available.
REVALIDATION_ENABLED = os.environ.get("REVALIDATION_ENABLED", "1") not in ("0", "false", "False", "")

# Import the new intelligence extensions
from intelligence_extensions import fetch_shodan_data, fetch_virustotal_passive_dns, fetch_virustotal_reputation, fetch_reverse_ip_lookup, correlate_ip_neighbors, identify_shared_infrastructure, EXPANDED_PHISHING_PATTERNS, fetch_subdomain_enumeration, check_social_media_presence, map_content_similarity, fetch_threatfox, fetch_otx_ip_passive_dns, fetch_otx_general, fetch_otx_domain_passive_dns, fetch_ip_hosted_domains_intel, fetch_gti_intel, fetch_circl_pdns, fetch_mnemonic_pdns
import pdns_store
import diff_engine
from pivot_intel import (fetch_seed_fingerprint, shodan_favicon_pivot,
                          censys_favicon_pivot, fetch_reverse_ns,
                          extract_jarms_from_shodan_results)
# Import IOC correlation engine
from ioc_correlation_engine import correlate_iocs_with_threat_feeds, analyze_correlation_results

# Import Threat Actor Attribution module

# Import ASN intelligence module
from asn_intelligence import ASNIntelligence, map_ip_to_asn, bulk_lookup_asns, analyze_hosting_patterns, generate_asn_report

# Import Cryptocurrency Intelligence module

# Import Automated Revalidation functions
from automated_revalidation import create_automated_revalidation_system

def validate_domain(raw: str) -> Optional[str]:
    s = re.sub(r'^https?://', '', raw.strip().lower())
    s = re.sub(r'/.*$', '', s)
    s = re.sub(r':\d+$', '', s)
    clean = s.lstrip('%.')
    if not clean or len(clean) > 253: return None
    return s if DOMAIN_RE.match(clean) else None

def validate_ip(raw: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(raw.strip())
        if ip.is_private or ip.is_loopback or ip.is_reserved: return None
        return str(ip)
    except ValueError:
        return None

def validate_seed(raw: str):
    d = validate_domain(raw)
    if d: return d, 'domain'
    ip = validate_ip(raw)
    if ip: return ip, 'ip'
    return None, 'invalid'

# ════════════════════════════════════════════════════════════
# REGISTRABLE DOMAIN (eTLD+1) EXTRACTION
# ════════════════════════════════════════════════════════════
# Given any FQDN or subdomain, return the "registered domain" — the shortest
# suffix a person can register (eTLD+1). For example:
#   r8cgf6ux.luxerabet100.com  ->  luxerabet100.com
#   a.b.example.co.uk         ->  example.co.uk
#   104.21.84.32              ->  None (not a domain)
#   x.example.com.            ->  example.com (trailing dot tolerated)
# Uses the embedded Public Suffix List bundled with the publicsuffix2 package,
# so multi-part public suffixes (co.uk, com.au, co.jp, com.br, etc.) are
# handled correctly without any network call.
def registrable_domain(raw: str) -> Optional[str]:
    if not raw: return None
    s = raw.strip().lower().rstrip('.')
    # Reject anything that's clearly an IP — the standard mode allows IP seeds
    # and we don't want to "extract" an eTLD+1 from a numeric address.
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass
    if not s or ' ' in s or len(s) > 253:
        return None
    # public_suffix2 returns the eTLD+1 ("registered domain") when given any
    # suffix of a registered name. If the input doesn't end in a known public
    # suffix, it returns None — which we surface as-is.
    try:
        sld = publicsuffix2.get_sld(s)
    except Exception:
        sld = None
    if sld and '.' in sld:
        return sld
    # Fallback for inputs the PSL doesn't know (e.g. brand-new gTLDs): take
    # the last two labels. This is the "drop the leftmost label" rule and
    # matches the user's example behavior.
    parts = s.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return None

# ════════════════════════════════════════════════════════════
# API FETCHERS
# ════════════════════════════════════════════════════════════

# Default CT source order — the free, reliable, no-key sources first (certspotter,
# certkit), then crt.sh as fallback, then Censys and pluggable providers. The first
# enabled source that returns results wins. Substring brand queries skip the
# exact-domain-only sources (certspotter, certkit) and lean on crt.sh / Censys / providers.
DEFAULT_CT_SOURCES = ["certspotter", "certkit", "crtsh", "censys", "scantower", "cloudflare"]

_DOMAINISH_RE = re.compile(r'(?:\*\.)?(?:[a-z0-9_-]+\.)+[a-z]{2,}')

def _ct_row(names, issuer="?", not_before="", source="ct") -> dict:
    """Normalize a cert record to the {name_value, issuer_name, not_before} shape
    the rest of the app consumes, regardless of which CT source produced it."""
    if isinstance(names, str): names = [names]
    return {"name_value": "\n".join(n for n in names if n),
            "issuer_name": issuer or "?", "not_before": not_before or "", "_source": source}

def _extract_domains_from_json(obj) -> set[str]:
    """Walk arbitrary JSON and pull out domain-like strings — used for pluggable CT
    providers whose response shape we don't know ahead of time."""
    found: set[str] = set()
    def walk(o):
        if isinstance(o, str):
            for m in _DOMAINISH_RE.findall(o.lower()):
                found.add(m.lstrip("*."))
        elif isinstance(o, dict):
            for v in o.values(): walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o: walk(v)
    walk(obj)
    return found

async def _ct_crtsh(query: str) -> tuple[bool, list[dict]]:
    """crt.sh JSON API. Slow/flaky on broad queries, so allow real time + retries."""
    rows, got = [], False
    for attempt in range(3):
        try:
            if attempt: await asyncio.sleep(attempt * 3)
            r = await client.get(f"https://crt.sh/?q={query}&output=json", timeout=90.0)
            if r.status_code == 200:
                got = True
                for d in (r.json() or []):
                    d["_source"] = "crtsh"
                    rows.append(d)
                break  # a 200 is authoritative — don't hammer crt.sh further
        except Exception:
            pass
    return got, rows

async def _ct_certspotter(base: str) -> tuple[bool, list[dict]]:
    """SSLMate Cert Spotter — the primary source: a real, documented CT API that is
    considerably more reliable than crt.sh. Free unauthenticated (low limits); a key
    raises them. Takes a concrete domain (no substring search)."""
    rows, got = [], False
    try:
        headers = {"Authorization": f"Bearer {CERTSPOTTER_API_KEY}"} if CERTSPOTTER_API_KEY else {}
        r = await client.get(
            f"https://api.certspotter.com/v1/issuances?domain={base}"
            f"&include_subdomains=true&expand=dns_names&expand=issuer&limit=1000",
            headers=headers, timeout=30.0)
        if r.status_code == 200:
            got = True
            for i in (r.json() or []):
                issuer = (i.get("issuer") or {}).get("name", "?")
                rows.append(_ct_row(i.get("dns_names", []), issuer, i.get("not_before", ""), "certspotter"))
    except Exception:
        pass
    return got, rows

async def _ct_certkit(base: str) -> tuple[bool, list[dict]]:
    """certkit.io CT search (ct.certkit.io/search). Free, no API key required — capped
    at 100 certs per query without a paid account. POST {domain, limit}; returns
    structured certs. Domain-exact + subdomains (no substring brand search). Reliable
    where crt.sh is flaky (e.g. it returns full results for reyesholdings.com)."""
    rows, got = [], False
    try:
        r = await client.post(
            "https://ct.certkit.io/search",
            json={"domain": base, "limit": 100},
            headers={"Content-Type": "application/json"}, timeout=30.0)
        if r.status_code == 200:
            got = True
            for c in (r.json().get("results") or []):
                names = c.get("dnsNames") or ([c["commonName"]] if c.get("commonName") else [])
                rows.append(_ct_row(names, c.get("issuerOrganization", "?"),
                                    c.get("notBefore", ""), "certkit"))
    except Exception:
        pass
    return got, rows

async def _ct_censys(base: str, is_substring: bool) -> tuple[bool, list[dict]]:
    """Censys certificate search (requires API ID:secret from Settings). Supports
    wildcard name queries, so it can do the substring brand search that crt.sh does —
    a real reliable alternative when crt.sh is down. Note: certificate search requires
    a Censys account with access to that dataset."""
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return False, []
    rows, got = [], False
    q = f"parsed.names: *{base}*" if is_substring else f"parsed.names: {base}"
    try:
        r = await client.post(
            "https://search.censys.io/api/v1/search/certificates",
            json={"query": q,
                  "fields": ["parsed.names", "parsed.issuer.organization", "parsed.validity.start"],
                  "per_page": 100},
            auth=(CENSYS_API_ID, CENSYS_API_SECRET), timeout=30.0)
        if r.status_code == 200:
            got = True
            for hit in (r.json().get("results") or []):
                issuer = hit.get("parsed.issuer.organization") or "?"
                if isinstance(issuer, list): issuer = issuer[0] if issuer else "?"
                rows.append(_ct_row(hit.get("parsed.names") or [], issuer,
                                    hit.get("parsed.validity.start", ""), "censys"))
    except Exception:
        pass
    return got, rows

async def _ct_provider(name: str, cfg: dict, base: str) -> tuple[bool, list[dict]]:
    """Generic pluggable CT provider (certkit.io / scantower.io / Cloudflare / any
    HTTP-JSON CT API). Requires both an API key and a URL template containing {q}.
    The response shape is unknown, so domain-like strings are extracted generically
    and filtered to the brand. Inert until configured in Settings."""
    key, url_tpl = cfg.get("key"), cfg.get("url")
    if not key or not url_tpl or "{q}" not in url_tpl:
        return False, []
    rows, got = [], False
    try:
        r = await client.get(url_tpl.format(q=base),
                             headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
                             timeout=30.0)
        if r.status_code == 200:
            got = True
            try: data = r.json()
            except Exception: data = r.text
            domains = (_extract_domains_from_json(data) if not isinstance(data, str)
                       else {m.lstrip("*.") for m in _DOMAINISH_RE.findall(data.lower())})
            for d in domains:
                if base in d:
                    rows.append(_ct_row([d], "?", "", name))
    except Exception:
        pass
    return got, rows

async def fetch_crtsh(domain: str, sources: set[str] | None = None) -> list[dict]:
    """Multi-source certificate-transparency lookup. Despite the legacy name, this
    aggregates several CT providers (certspotter → crt.sh → Censys → pluggable) and
    returns the first enabled source that yields results — so a crt.sh outage no longer
    breaks discovery. Source selection is driven by the Settings tab toggles.

    A bare brand label wrapped in % (e.g. "%paypal%") is treated as a substring brand
    search; otherwise the input is a concrete domain and we query its wildcard subtree."""
    enabled = set(sources) if sources is not None else set(DEFAULT_CT_SOURCES)

    is_substring = "%" in domain
    if is_substring:
        base = domain.strip("%").lstrip("*.")
        crtsh_query = domain
    else:
        base = domain.lstrip("*.")
        crtsh_query = f"%.{base}"

    # Track whether any source actually answered (HTTP 200). An empty-but-successful
    # response (a brand with zero lookalikes) is a valid "0 results" answer, not a
    # failure — only raise when every enabled source errored or timed out.
    results, got_response = [], False
    for src in DEFAULT_CT_SOURCES:
        if src not in enabled or results:
            continue
        try:
            if src == "certspotter":
                if is_substring or "." not in base:
                    continue  # certspotter has no substring search
                got, rows = await _ct_certspotter(base)
            elif src == "certkit":
                if is_substring or "." not in base:
                    continue  # certkit is exact-domain only — no substring search
                got, rows = await _ct_certkit(base)
            elif src == "crtsh":
                got, rows = await _ct_crtsh(crtsh_query)
            elif src == "censys":
                got, rows = await _ct_censys(base, is_substring)
            elif src in CT_PROVIDERS:
                got, rows = await _ct_provider(src, CT_PROVIDERS[src], base)
            else:
                continue
        except Exception:
            got, rows = False, []
        got_response = got_response or got
        results.extend(rows)

    if results or got_response:
        return results
    raise RuntimeError("No certificate transparency sources available")

async def _ct_summary_for_domain(domain: str) -> dict | None:
    """Look up CT certs for a single domain via certspotter (fast, reliable) and
    return a compact summary. Returns None on failure / empty so the caller can
    drop unknown domains cleanly. crt.sh is intentionally not used here — for an
    N-domain enrichment loop, a single crt.sh outage shouldn't slow the lot."""
    try:
        got, rows = await _ct_certspotter(domain)
    except Exception:
        return None
    if not got or not rows:
        return None
    dates = [r.get("not_before","") for r in rows if r.get("not_before")]
    dates.sort()
    return {
        "domain": domain,
        "cert_count": len(rows),
        "first_seen": dates[0][:10] if dates else "",
        "last_seen":  dates[-1][:10] if dates else "",
        "source": "certspotter",
    }

async def enrich_neighbors_with_ct(domains: list[str], limit: int = 25,
                                   concurrency: int = 5) -> list[dict]:
    """Run CT lookups on a deduped, capped set of neighbor / IP-hosted domains.
    Used after reverse-IP and reverse-NS settle so the analyst can see, per
    neighbor, when the domain first showed up in CT logs (issuance bursts are a
    campaign signal, even when the neighbor itself looks unrelated)."""
    seen, ordered = set(), []
    for d in domains:
        if not d: continue
        key = d.lower().strip(".")
        if key in seen: continue
        seen.add(key)
        ordered.append(key)
        if len(ordered) >= limit: break
    if not ordered:
        return []
    sem = asyncio.Semaphore(concurrency)
    async def _bounded(d):
        async with sem:
            return await _ct_summary_for_domain(d)
    results = await asyncio.gather(*[_bounded(d) for d in ordered], return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]

async def fetch_dns(name: str, rtype: str = "A") -> dict:
    r = await client.get(f"https://dns.google/resolve?name={name}&type={rtype}",
                         headers={"Accept":"application/dns-json"}, timeout=8.0)
    r.raise_for_status()
    return r.json()

# Name fragments of large hosting/CDN providers. An IP here that serves many domains is
# shared infrastructure — co-location is NOT evidence of a relationship.
MAJOR_HOSTING_PROVIDERS = (
    "amazon", "aws", "cloudflare", "google", "microsoft", "azure", "digitalocean",
    "ovh", "hetzner", "akamai", "fastly", "linode", "oracle", "alibaba", "tencent",
    "godaddy", "namecheap", "hostinger", "squarespace", "wix", "shopify", "automattic",
    "wordpress", "vercel", "netlify", "leaseweb", "contabo", "scaleway", "gcore",
    "stackpath", "incapsula", "sucuri", "ionos", "namesilo", "porkbun", "plesk",
)
_CDN_PROVIDERS = ("cloudflare", "akamai", "fastly", "incapsula", "sucuri", "stackpath", "gcore")

def classify_ip_hosting(info: dict, domain_count: int) -> dict:
    """Decide whether an IP is shared hosting / CDN, where co-located domains are NOT
    evidence of relatedness — so one malicious domain doesn't make the IP malicious."""
    name = f"{info.get('isp','')} {info.get('asname','')} {info.get('org','')}".lower()
    is_major = any(p in name for p in MAJOR_HOSTING_PROVIDERS)
    is_cdn = any(p in name for p in _CDN_PROVIDERS)
    many = domain_count >= 50
    shared = (is_major or is_cdn) and many
    verdict = None
    if shared:
        verdict = (f"SHARED HOSTING — {info.get('isp','this provider')} serves {domain_count}+ domains on "
                   f"this IP. Co-location here is not evidence of a relationship; do NOT treat the IP as "
                   f"malicious just because one hosted domain is.")
    elif is_cdn:
        verdict = (f"{info.get('isp','CDN')} CDN — the true origin IP is hidden and co-hosted domains are "
                   f"unrelated. Pivot on the origin, not this shared edge IP.")
    return {"is_major_provider": is_major, "is_cdn": is_cdn, "shared_hosting": shared,
            "domain_count": domain_count, "verdict": verdict}

async def fetch_ipinfo(ip: str) -> dict:
    # freeipapi — no auth, no CORS issues server-side
    try:
        r = await client.get(f"https://freeipapi.com/api/json/{ip}", timeout=8.0)
        if r.status_code == 200:
            d = r.json()
            asn_num = d.get("asn")
            is_hosting = (
                d.get("ipType") in ("datacenter", "business", "education", "government")
                or (asn_num and int(asn_num) in DATACENTER_ASNS)
            )
            return {
                "query": ip, "country": d.get("countryName", "?"),
                "countryCode": d.get("countryCode", "?"),
                "regionName": d.get("regionName", "?"), "city": d.get("cityName", "?"),
                "isp": d.get("asnOrganization", "?"), "org": d.get("asnOrganization", "?"),
                "as": f"AS{asn_num}" if asn_num else "?",
                "asname": d.get("asnOrganization", "?"),
                "hosting": is_hosting, "proxy": d.get("isProxy", False),
                "mobile": d.get("ipType") == "mobile", "_source": "freeipapi",
            }
    except Exception:
        pass
    # ip-api.com fallback — HTTP is fine server-side, no CORS restriction
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"regionName,city,isp,org,as,asname,hosting,proxy,query,mobile", timeout=8.0)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                d["_source"] = "ip-api"
                return d
    except Exception:
        pass
    raise RuntimeError(f"IP enrichment failed for {ip}")

async def fetch_rdap(domain: str) -> dict:
    for url in [f"https://rdap.org/domain/{domain}",
                f"https://rdap.verisign.com/com/v1/domain/{domain.upper()}"]:
        try:
            r = await client.get(url, headers={"Accept":"application/rdap+json"}, timeout=12.0)
            if r.status_code == 200: return r.json()
        except Exception:
            continue
    raise RuntimeError(f"RDAP unavailable for {domain}")

async def fetch_whois_public(domain: str) -> Optional[dict]:
    """Passive WHOIS via the free who-dat public API (no key). Covers TLDs that don't
    expose RDAP — many ccTLDs/new gTLDs like .io, .co, .icu return RDAP 404 but have
    WHOIS. Returns the parse_rdap_summary shape (+ source/registered) or None."""
    try:
        r = await client.get(f"https://who-dat.as93.net/{domain}", timeout=15.0)
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("isRegistered") is False:
            return {"handle": "?", "registrar": "(not registered)", "status": "not registered",
                    "created": "?", "updated": "?", "expires": "?", "nameservers": "",
                    "source": "whois", "registered": False}
        dates = d.get("dates") or {}
        ns = [n.get("name", "") for n in (d.get("nameservers") or []) if isinstance(n, dict) and n.get("name")]
        status = d.get("status") or []
        return {
            "handle": str(d.get("id") or "?"),
            "registrar": (d.get("registrar") or {}).get("name") or "?",
            "status": ", ".join(status) if isinstance(status, list) else str(status),
            "created": dates.get("created") or "?",
            "updated": dates.get("updated") or "?",
            "expires": dates.get("expires") or "?",
            "nameservers": ", ".join(ns),
            "source": "whois", "registered": True,
        }
    except Exception:
        return None

async def fetch_domain_registration(domain: str) -> dict:
    """Unified registration lookup — RDAP first (authoritative/structured), then passive
    public WHOIS (who-dat) for TLDs RDAP doesn't cover. Both are public web services, so
    this stays passive. Returns the parse_rdap_summary shape plus a 'source' field."""
    try:
        summary = parse_rdap_summary(await fetch_rdap(domain))
        if summary.get("registrar", "?") != "?" or summary.get("created", "?") != "?":
            summary["source"] = "rdap"
            return summary
    except Exception:
        pass
    whois = await fetch_whois_public(domain)
    if whois:
        return whois
    raise RuntimeError(f"No registration data (RDAP or WHOIS) for {domain}")

async def fetch_urlscan(seed: str) -> dict:
    """urlscan.io — free, no auth needed for search, ~1000 req/day unauthenticated.

    Routes by seed kind: IP seeds use `page.ip:`, domain seeds use `domain:`. A
    `domain:` query against an IP returns nothing, so always classify first."""
    is_ip = validate_ip(seed) is not None
    query = f"page.ip:%22{seed}%22" if is_ip else f"domain:{seed}"
    try:
        r = await client.get(
            f"https://urlscan.io/api/v1/search/?q={query}&size=20",
            headers={"Accept": "application/json"}, timeout=15.0)
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            screenshots, ips_seen, asns = [], set(), set()
            for res in results:
                page = res.get("page", {})
                if page.get("ip"): ips_seen.add(page["ip"])
                if page.get("asn"): asns.add(page["asn"])
                if res.get("screenshot"): screenshots.append(res["screenshot"])
            return {
                "total": data.get("total", 0), "results": results[:10],
                "unique_ips": list(ips_seen), "unique_asns": list(asns),
                "screenshots": screenshots[:3],
            }
    except Exception:
        pass
    return {"total": 0, "results": [], "unique_ips": [], "unique_asns": [], "screenshots": []}

async def fetch_domains_on_ip(ip: str) -> list[str]:
    """Find domains historically observed on an IP via urlscan.io (page.ip search).
    Complements HackerTarget reverse-IP, which has a weak/rate-limited free tier."""
    domains = set()
    try:
        r = await client.get(
            f"https://urlscan.io/api/v1/search/?q=page.ip:%22{ip}%22&size=100",
            headers={"Accept": "application/json"}, timeout=15.0)
        if r.status_code == 200:
            for res in r.json().get("results", []):
                d = (res.get("page", {}).get("domain") or "").strip().lower().rstrip(".")
                if d and DOMAIN_RE.match(d):
                    domains.add(d)
    except Exception:
        pass
    return sorted(domains)

async def fetch_cert_timeline(domain: str, certs: list[dict]) -> list[dict]:
    """Build cert issuance timeline from crt.sh results."""
    timeline = []
    for c in certs:
        date_str = c.get("not_before","")
        if not date_str: continue
        try:
            dt = datetime.fromisoformat(date_str.replace("Z","+00:00"))
            names = [n.strip().lstrip("*.") for n in (c.get("name_value","")).split("\n") if n.strip()]
            timeline.append({
                "date": dt.strftime("%Y-%m-%d"),
                "month": dt.strftime("%Y-%m"),
                "issuer": (c.get("issuer_name","?").split("O=")[1].split(",")[0] if "O=" in c.get("issuer_name","") else "?"),
                "names": names[:3],
                "count": len(names),
            })
        except Exception:
            pass
    timeline.sort(key=lambda x: x["date"])
    return timeline

# ════════════════════════════════════════════════════════════
# SSL CERTIFICATE GRAPH ANALYSIS
# ════════════════════════════════════════════════════════════

def build_certificate_graph(certs: list[dict]) -> dict:
    """
    Build a graph representation of certificate relationships to identify:
    - Shared certificate attributes
    - Certificate families (domains using same issuing patterns)
    - Issuer migration patterns
    - Suspicious certificate chains
    """
    # Initialize graph structure
    graph = {
        "nodes": [],  # Domains and issuers as nodes
        "edges": [],  # Relationships between domains/issuers
        "certificate_families": [],
        "issuer_migrations": [],
        "suspicious_chains": [],
        "issuer_statistics": {}
    }
    
    # Track domain to issuer relationships
    domain_issuers = {}
    issuer_domains = {}
    issuer_cert_counts = {}
    
    # Process certificates and build relationships
    for cert in certs:
        names = [n.strip().lstrip("*.").lower() for n in cert.get("name_value", "").split("\n") if n.strip()]
        issuer = cert.get("issuer_name", "?")
        
        # Extract organization from issuer name
        issuer_org = "?"
        if "O=" in issuer:
            issuer_org = issuer.split("O=")[1].split(",")[0]
        
        # Track issuer statistics
        issuer_cert_counts[issuer_org] = issuer_cert_counts.get(issuer_org, 0) + 1
        
        # Connect domains to their issuers
        for name in names:
            if name:
                # Domain to issuer mapping
                domain_issuers[name] = issuer_org
                
                # Issuer to domains mapping
                if issuer_org not in issuer_domains:
                    issuer_domains[issuer_org] = []
                if name not in issuer_domains[issuer_org]:
                    issuer_domains[issuer_org].append(name)
    
    # Identify certificate families (issuers with many domains)
    certificate_families = []
    for issuer, domains in issuer_domains.items():
        if len(domains) > 3:  # Threshold for family classification
            certificate_families.append({
                "issuer": issuer,
                "domain_count": len(domains),
                "domains": domains[:20],  # Limit to 20 for display
                "family_size": "large" if len(domains) > 10 else "medium" if len(domains) > 5 else "small"
            })
    
    # Identify issuer migration patterns (domains with multiple issuers over time)
    issuer_migrations = []
    domain_issuer_history = {}
    
    # Group certificates by domain
    for cert in certs:
        names = [n.strip().lstrip("*.").lower() for n in cert.get("name_value", "").split("\n") if n.strip()]
        issuer = cert.get("issuer_name", "?")
        issuer_org = "?" 
        if "O=" in issuer:
            issuer_org = issuer.split("O=")[1].split(",")[0]
            
        not_before = cert.get("not_before", "")
        
        for name in names:
            if name:
                if name not in domain_issuer_history:
                    domain_issuer_history[name] = []
                domain_issuer_history[name].append({
                    "issuer": issuer_org,
                    "date": not_before
                })
    
    # Find domains with multiple issuers
    for domain, history in domain_issuer_history.items():
        if len(set(entry["issuer"] for entry in history)) > 1:
            # Sort by date
            sorted_history = sorted(history, key=lambda x: x["date"])
            issuer_migrations.append({
                "domain": domain,
                "issuer_sequence": sorted_history,
                "migration_count": len(sorted_history)
            })
    
    # Flag suspicious certificate chains
    suspicious_chains = []
    suspicious_issuers = ["?"]  # Unknown issuers are suspicious
    
    for cert in certs:
        names = [n.strip().lstrip("*.").lower() for n in cert.get("name_value", "").split("\n") if n.strip()]
        issuer = cert.get("issuer_name", "?")
        issuer_org = "?" 
        if "O=" in issuer:
            issuer_org = issuer.split("O=")[1].split(",")[0]
            
        # Check for suspicious patterns
        if issuer_org in suspicious_issuers or issuer_org == "?":
            for name in names:
                if name:
                    suspicious_chains.append({
                        "domain": name,
                        "issuer": issuer_org,
                        "reason": "Unknown or suspicious issuer"
                    })
    
    # Update graph with analysis results
    graph["certificate_families"] = certificate_families
    graph["issuer_migrations"] = issuer_migrations[:20]  # Limit for display
    graph["suspicious_chains"] = suspicious_chains[:20]  # Limit for display
    graph["issuer_statistics"] = issuer_cert_counts
    
    return graph

def calculate_certificate_risk_score(graph: dict) -> int:
    """
    Calculate a risk score based on certificate graph analysis.
    Higher score indicates more suspicious certificate patterns.
    """
    risk_score = 0
    
    # Risk from certificate families
    large_families = [f for f in graph["certificate_families"] if f["family_size"] == "large"]
    risk_score += len(large_families) * 10
    
    # Risk from issuer migrations
    risk_score += len(graph["issuer_migrations"]) * 5
    
    # Risk from suspicious chains
    risk_score += len(graph["suspicious_chains"]) * 15
    
    # Cap at 100
    return min(100, risk_score)

async def fetch_extended_certificate_analysis(certs: list[dict]) -> dict:
    """
    Perform extended certificate analysis including graph relationships.
    """
    try:
        graph = build_certificate_graph(certs)
        risk_score = calculate_certificate_risk_score(graph)
        
        return {
            "graph": graph,
            "risk_score": risk_score,
            "analysis_complete": True
        }
    except Exception as e:
        return {
            "graph": {},
            "risk_score": 0,
            "analysis_complete": False,
            "error": str(e)
        }

# ════════════════════════════════════════════════════════════
# TYPOSQUATTING / DNSTWIST
# ════════════════════════════════════════════════════════════

async def fetch_typosquatting(domain: str) -> list[dict]:
    """
    Use DNSTwist to find potential typosquatting domains.
    Returns a list of potential typosquatting domains with their properties.
    """
    try:
        # Check if dnstwist is available
        result = subprocess.run(['dnstwist', '--help'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError("DNSTwist not available")
        
        # Run dnstwist with JSON output
        # Using a shorter timeout for safety
        result = subprocess.run([
            'dnstwist', 
            '--format', 'json',
            '--threads', '10',
            '--timeout', '5',
            domain
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                # Filter out the original domain and format the results
                typosquats = []
                for entry in data:
                    if isinstance(entry, dict) and 'domain' in entry:
                        domain_name = entry.get('domain', '')
                        if domain_name and domain_name != domain:
                            typosquats.append({
                                'domain': domain_name,
                                'fuzzer': entry.get('fuzzer', 'unknown'),
                                'dns_a': entry.get('dns_a', []),
                                'dns_aaaa': entry.get('dns_aaaa', []),
                                'dns_mx': entry.get('dns_mx', []),
                                'dns_ns': entry.get('dns_ns', []),
                                'strength': calculate_typosquatting_strength(domain, domain_name)
                            })
                return typosquats[:100]  # Limit to 100 results
            except json.JSONDecodeError:
                pass
        
        # Fallback to simple domain manipulation if DNSTwist fails
        return generate_simple_typos(domain)
        
    except subprocess.TimeoutExpired:
        # If DNSTwist times out, fall back to simple generation
        return generate_simple_typos(domain)
    except Exception as e:
        # If anything else fails, fall back to simple generation
        return generate_simple_typos(domain)

def calculate_typosquatting_strength(original: str, typo: str) -> int:
    """
    Calculate a strength score for typosquatting based on similarity.
    Higher score = more likely to be malicious.
    """
    score = 0
    
    # Common brand impersonation patterns (higher score)
    if any(pattern in typo for pattern in ['login', 'secure', 'account', 'verify', 'update']):
        score += 30
    
    # TLD similarity (exact match gets high score)
    orig_parts = original.split('.')
    typo_parts = typo.split('.')
    if len(orig_parts) >= 2 and len(typo_parts) >= 2:
        if orig_parts[-1] == typo_parts[-1]:  # Same TLD
            score += 20
        # Common TLD swaps
        elif (orig_parts[-1] == 'com' and typo_parts[-1] in ['net', 'org', 'co']) or \
             (orig_parts[-1] == 'net' and typo_parts[-1] in ['com', 'org']) or \
             (orig_parts[-1] == 'org' and typo_parts[-1] in ['com', 'net']):
            score += 15
    
    # Character similarity (Levenshtein distance approach)
    from difflib import SequenceMatcher
    similarity = SequenceMatcher(None, original, typo).ratio()
    score += int(similarity * 40)
    
    # Length similarity
    len_diff = abs(len(original) - len(typo))
    if len_diff == 0:
        score += 10
    elif len_diff <= 2:
        score += 5
    
    # Suspicious TLDs (higher risk)
    if typo_parts[-1] in ['tk', 'ml', 'ga', 'cf', 'ru', 'info', 'biz']:
        score += 15
    
    return min(100, score)  # Cap at 100

def generate_simple_typos(domain: str) -> list[dict]:
    """
    Generate simple typosquatting domains using common techniques.
    This is a fallback when DNSTwist is not available.
    """
    if '.' not in domain:
        return []
    
    parts = domain.split('.')
    base_domain = parts[0] if len(parts) > 1 else domain
    tld = parts[-1] if len(parts) > 1 else 'com'
    
    typos = []
    common_tlds = ['com', 'net', 'org', 'co', 'io', 'ai', 'tech']
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'info', 'biz']
    
    # Common typosquatting techniques
    techniques = [
        # Bit flips
        (base_domain.replace('o', '0'), 'bitflip_o'),
        (base_domain.replace('l', '1'), 'bitflip_l'),
        (base_domain.replace('e', '3'), 'bitflip_e'),
        (base_domain.replace('a', '4'), 'bitflip_a'),
        (base_domain.replace('s', '5'), 'bitflip_s'),
        (base_domain.replace('t', '7'), 'bitflip_t'),
        # Duplicates
        (base_domain + base_domain[-1], 'duplicate'),
        # Omissions
        (base_domain[1:], 'omission_first'),
        (base_domain[:-1], 'omission_last'),
        # Transpositions
        (base_domain[1] + base_domain[0] + base_domain[2:], 'transposition'),
    ]
    
    # Add common TLD variations
    for base, technique in techniques:
        if len(base) > 2 and base != base_domain:
            # Common TLDs
            for t in common_tlds:
                if t != tld:
                    typos.append({
                        'domain': f"{base}.{t}",
                        'fuzzer': technique,
                        'dns_a': [],
                        'dns_aaaa': [],
                        'dns_mx': [],
                        'dns_ns': [],
                        'strength': calculate_typosquatting_strength(domain, f"{base}.{t}")
                    })
            
            # Suspicious TLDs (higher risk score)
            for t in suspicious_tlds:
                typos.append({
                    'domain': f"{base}.{t}",
                    'fuzzer': technique + '_suspicious',
                    'dns_a': [],
                    'dns_aaaa': [],
                    'dns_mx': [],
                    'dns_ns': [],
                    'strength': calculate_typosquatting_strength(domain, f"{base}.{t}") + 10
                })
    
    # Sort by strength (descending) and return top 50
    typos.sort(key=lambda x: x['strength'], reverse=True)
    return typos[:50]

# ════════════════════════════════════════════════════════════
# DOMAIN EXTRACTION
# ════════════════════════════════════════════════════════════

def extract_domains_from_certs(certs: list[dict], seed: str) -> list[dict]:
    seen = {seed}
    seed_label = seed.rsplit(".", 1)[0] if "." in seed else seed
    domains = [{"name": seed, "source": "seed", "flag": None,
                "entropy": round(shannon_entropy(seed_label), 2)}]
    for c in certs:
        for name in (c.get("name_value") or "").split("\n"):
            n = name.strip().lower().lstrip("*.")
            if n and n not in seen and DOMAIN_RE.match(n):
                seen.add(n)
                flag = "NEIBU" if n.startswith("neibu") else None
                src = "certspotter" if c.get("_source") == "certspotter" else "cert"
                label = n.rsplit(".", 1)[0] if "." in n else n
                domains.append({"name": n, "source": src, "flag": flag,
                                 "entropy": round(shannon_entropy(label), 2)})
    return domains

# ════════════════════════════════════════════════════════════
# THREAT SCORING — 12 signals, weighted additive model
# ════════════════════════════════════════════════════════════

def shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy of a string in bits.
    High entropy (>3.5) = likely machine-generated / DGA domain.
    Low entropy (<2.5)  = human-readable / brand name.

    Signal suggested by Ryan McDonald as a valuable weight for surfacing
    dynamically-generated domain infrastructure within a CT cluster.
    Reference: Dark Reading tutorials on DGA entropy analysis.
    """
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def parse_rdap_summary(rdap: dict) -> dict:
    events = {e["eventAction"]: e["eventDate"] for e in rdap.get("events",[])}
    registrar = "?"
    for e in rdap.get("entities",[]):
        if "registrar" in e.get("roles",[]):
            for field in e.get("vcardArray",[[],([])])[1]:
                if field[0]=="fn": registrar=field[3]; break
    nameservers = [ns.get("ldhName","") for ns in rdap.get("nameservers",[])]
    return {"handle":rdap.get("handle","?"),"registrar":registrar,
            "status":", ".join(rdap.get("status",[])),"created":events.get("registration","?"),
            "updated":events.get("last changed","?"),"expires":events.get("expiration","?"),
            "nameservers":", ".join(nameservers)}

# ════════════════════════════════════════════════════════════
# SSE PIPELINE
# ════════════════════════════════════════════════════════════

# Tag set that indicates an OTX pulse is about live malware / attacker tooling
# rather than (e.g.) a generic vulnerability advisory. Match is case-insensitive
# and against the pulse's `tags` array.
_OTX_MALICIOUS_TAGS = frozenset({
    "ransomware", "rat", "trojan", "stealer", "infostealer", "loader",
    "backdoor", "botnet", "c2", "c&c", "command and control",
    "spyware", "rootkit", "wiper", "phishing", "skimmer", "magecart",
    "apt", "intrusion", "exploit-kit", "exploit kit",
})


def _findings_from_otx_pulses(otx_general: dict, *, context_seed: str = "") -> list:
    """Convert OTX pulse memberships into structured findings.

    Severity tiers:
      critical — pulse advertises named malware_families
      high     — pulse tags overlap _OTX_MALICIOUS_TAGS but no named family
      (other pulses are skipped — too noisy)
    """
    findings = []
    seen = set()
    for entry in (otx_general.get("per_seed") or []):
        if entry.get("error"):
            continue
        seed = entry.get("seed", "")
        for pulse in (entry.get("pulses") or []):
            pulse_name = pulse.get("name") or ""
            pulse_id = pulse.get("id") or ""
            tags = {str(t).lower() for t in (pulse.get("tags") or [])}
            attack_ids = pulse.get("attack_ids") or []
            families = pulse.get("malware_families") or []

            pulse_url = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else ""

            if families:
                for fam in families[:3]:
                    fam_name = (
                        fam.get("display_name") or fam.get("name")
                        if isinstance(fam, dict) else str(fam)
                    )
                    if not fam_name:
                        continue
                    key = ("fam", fam_name.lower(), seed)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "severity": "critical", "category": "otx",
                        "title": f"{fam_name} (OTX pulse)",
                        "message": (
                            f"{fam_name} associated with {seed} "
                            f"(OTX pulse '{pulse_name}')"
                        ),
                        "url": pulse_url,
                        "details": {
                            "seed": seed, "pulse_id": pulse_id,
                            "pulse_name": pulse_name,
                            "pulse_url": pulse_url,
                            "malware_family": fam_name,
                            "tags": sorted(tags), "attack_ids": attack_ids,
                            "author": pulse.get("author_name"),
                            "modified": pulse.get("modified"),
                        },
                        "source": "otx",
                        "seed": context_seed or seed,
                    })
                continue
            tag_hits = sorted(tags & _OTX_MALICIOUS_TAGS)
            if tag_hits:
                key = ("tags", tuple(tag_hits), seed)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "severity": "high", "category": "otx",
                    "title": f"OTX pulse: {', '.join(tag_hits)}",
                    "message": (
                        f"OTX pulse '{pulse_name}' tagged {','.join(tag_hits)} "
                        f"for {seed}"
                    ),
                    "url": pulse_url,
                    "details": {
                        "seed": seed, "pulse_id": pulse_id,
                        "pulse_name": pulse_name,
                        "pulse_url": pulse_url,
                        "tags": sorted(tags), "attack_ids": attack_ids,
                        "author": pulse.get("author_name"),
                        "modified": pulse.get("modified"),
                    },
                    "source": "otx",
                    "seed": context_seed or seed,
                })
    return findings


def _findings_from_vt(vt_rep: dict, *, context_seed: str = "") -> list:
    """VirusTotal reputation → finding when vendor counts / reputation cross
    thresholds. Tiered: 5+ malicious or rep<=-50 → critical; 1+ malicious or
    rep<=-25 → high; 3+ suspicious → medium; otherwise no finding."""
    if not vt_rep or "error" in vt_rep or vt_rep.get("not_found"):
        return []
    seed = vt_rep.get("ip") or vt_rep.get("domain") or context_seed or ""
    malicious = int(vt_rep.get("malicious", 0) or 0)
    suspicious = int(vt_rep.get("suspicious", 0) or 0)
    reputation = int(vt_rep.get("reputation", 0) or 0)
    total = int(vt_rep.get("total", 0) or 0)

    if malicious >= 5 or reputation <= -50:
        severity = "critical"
    elif malicious >= 1 or reputation <= -25:
        severity = "high"
    elif suspicious >= 3:
        severity = "medium"
    else:
        return []

    return [{
        "severity": severity, "category": "virustotal",
        "title": f"VT verdict: {vt_rep.get('verdict', 'unknown')}",
        "message": (
            f"VirusTotal flagged {seed}: {malicious}/{total} malicious, "
            f"{suspicious} suspicious, reputation {reputation}"
        ),
        "url": vt_rep.get("permalink") or "",
        "details": {
            "seed": seed,
            "malicious": malicious, "suspicious": suspicious,
            "harmless": vt_rep.get("harmless"),
            "undetected": vt_rep.get("undetected"),
            "reputation": reputation, "total": total,
            "verdict": vt_rep.get("verdict"),
            "permalink": vt_rep.get("permalink"),
        },
        "source": "virustotal",
        "seed": context_seed or seed,
    }]


def _findings_from_gti(gti_data: dict, *, context_seed: str = "") -> list:
    """Google Threat Intelligence → findings for any populated relationship
    (threat actors / malware families / campaigns / Mandiant attribution).
    Relationships only populate on GTI-entitled keys; standard VT keys yield
    nothing here, which is correct."""
    if not gti_data or "error" in gti_data or not gti_data.get("found"):
        return []
    findings = []
    seed = gti_data.get("seed") or context_seed or ""
    permalink = gti_data.get("permalink")

    threat_actors = gti_data.get("threat_actors") or []
    malware_families = gti_data.get("malware_families") or []
    campaigns = gti_data.get("campaigns") or []
    mandiant_attr = gti_data.get("mandiant_attribution") or {}

    def _names(items, cap=3):
        out = []
        for it in items[:cap]:
            n = it.get("name") if isinstance(it, dict) else ""
            n = n or (it.get("id") if isinstance(it, dict) else str(it))
            if n:
                out.append(n)
        return out

    if threat_actors:
        names = _names(threat_actors)
        findings.append({
            "severity": "critical", "category": "gti",
            "title": "GTI threat actor attribution",
            "message": f"GTI attributes {seed} to threat actor(s): {', '.join(names) or '(unnamed)'}",
            "url": permalink or "",
            "details": {"seed": seed, "actors": threat_actors, "permalink": permalink},
            "source": "gti", "seed": context_seed or seed,
        })
    if malware_families:
        names = _names(malware_families)
        findings.append({
            "severity": "critical", "category": "gti",
            "title": "GTI malware family",
            "message": f"GTI associates {seed} with malware: {', '.join(names) or '(unnamed)'}",
            "url": permalink or "",
            "details": {"seed": seed, "families": malware_families, "permalink": permalink},
            "source": "gti", "seed": context_seed or seed,
        })
    if campaigns:
        names = _names(campaigns)
        findings.append({
            "severity": "high", "category": "gti",
            "title": "GTI campaign association",
            "message": f"GTI links {seed} to campaign(s): {', '.join(names) or '(unnamed)'}",
            "url": permalink or "",
            "details": {"seed": seed, "campaigns": campaigns, "permalink": permalink},
            "source": "gti", "seed": context_seed or seed,
        })
    if mandiant_attr:
        findings.append({
            "severity": "high", "category": "gti",
            "title": "GTI/Mandiant attribution data",
            "message": f"GTI/Mandiant attribution data present for {seed}",
            "url": permalink or "",
            "details": {"seed": seed, "mandiant": mandiant_attr, "permalink": permalink},
            "source": "gti", "seed": context_seed or seed,
        })
    # GTI assessment (verdict + severity + score) is a finding on its own —
    # even without relationships, "Mandiant analyst marked this malicious" is
    # high-signal.
    assessment = gti_data.get("gti_assessment") or {}
    if isinstance(assessment, dict) and assessment:
        verdict = assessment.get("verdict") or assessment.get("threat_verdict") or ""
        severity_label = assessment.get("severity") or assessment.get("threat_severity") or ""
        score = assessment.get("threat_score") or assessment.get("gti_score") or assessment.get("score")
        if str(verdict).lower() in ("malicious", "harmful"):
            sev = "critical"
        elif str(verdict).lower() in ("suspicious",):
            sev = "high"
        elif score is not None and isinstance(score, (int, float)) and score >= 70:
            sev = "critical"
        elif score is not None and isinstance(score, (int, float)) and score >= 40:
            sev = "high"
        else:
            sev = ""
        if sev:
            findings.append({
                "severity": sev, "category": "gti",
                "title": f"GTI verdict: {verdict or 'flagged'}",
                "message": (
                    f"GTI assessment for {seed}: verdict={verdict or '?'}"
                    + (f", severity={severity_label}" if severity_label else "")
                    + (f", score={score}" if score is not None else "")
                ),
                "url": permalink or "",
                "details": {"seed": seed, "assessment": assessment,
                            "permalink": permalink},
                "source": "gti", "seed": context_seed or seed,
            })
    return findings


def _findings_from_threatfox(tf_data: dict, *, context_seed: str = "") -> list:
    """Convert ThreatFox matches into structured `finding` events so high-value
    hits (named malware families, threat types) get rendered prominently in the
    UI rather than scrolling past in the execution log.

    Severity tiers:
      critical — named malware family (Quasar RAT, AsyncRAT, Cobalt Strike, …)
      high     — threat_type only, no named family (e.g. "botnet_cc")
      (matches without either are skipped — nothing actionable to elevate)
    """
    findings = []
    for m in (tf_data.get("matches") or []):
        malware = (m.get("malware") or "").strip()
        threat_type = (m.get("threat_type") or "").strip()
        ioc = m.get("ioc") or ""
        ioc_type = m.get("ioc_type") or ""
        if malware:
            severity, label = "critical", malware
        elif threat_type:
            severity, label = "high", threat_type
        else:
            continue
        matched_by = m.get("matched_by") or []
        if "ip" in matched_by and "seed" in matched_by:
            via = "seed+IP"
        elif "ip" in matched_by:
            via = "IP"
        elif "seed" in matched_by:
            via = "seed"
        else:
            via = "?"
        findings.append({
            "severity": severity,
            "category": "threatfox",
            "title": f"{label} association",
            "message": f"{label} associated with {ioc} [{ioc_type}] via {via}",
            "details": {
                "ioc": ioc, "ioc_type": ioc_type,
                "malware": malware, "threat_type": threat_type,
                "first_seen": m.get("first_seen"),
                "last_seen": m.get("last_seen"),
                "confidence": m.get("confidence"),
                "reporter": m.get("reporter"),
                "reference": m.get("reference"),
                "tags": m.get("tags") or [],
                "matched_by": matched_by,
            },
            "source": "threatfox",
            "seed": context_seed,
        })
    return findings


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

class _StageDisabled(Exception):
    """Raised at the top of a pipeline stage when that stage is turned off in
    the Settings tab, so the stage's existing try/except cleanly skips its work."""
    pass

async def run_standard_pipeline(seed: str, ct_sources: set[str] | None = None, features: set[str] | None = None):
    result = {"seed":seed,"domains":[],"dns":{},"ip_results":[],"rdap":None,
              "urlscan":{},"cert_timeline":[],"infrastructure_timeline":[]}

    # Settings from the Settings tab. Default to everything enabled when not supplied.
    if ct_sources is None:
        ct_sources = set(DEFAULT_CT_SOURCES)
    if features is None:
        features = {"reverse_ip","asn_intel","ssl_graph","timeline","correlation",
                    "social_fingerprint","subdomain_discovery","revalidation"}
    def feat(name: str) -> bool: return name in features

    # An IP seed runs an infrastructure-pivot variant: cert-transparency / DNS-record /
    # typosquatting / subdomain stages are domain-only and are skipped or replaced
    # (reverse-IP domain discovery), while IP intel / ASN / reverse-IP / Shodan run on
    # the seed IP directly.
    is_ip = validate_ip(seed) is not None

    yield sse("log",{"msg":f"Pipeline v5.1 initiated for: {seed} ({'IP address' if is_ip else 'domain'})","type":"info","stage":"INIT"})
    yield sse("log",{"msg":"Discovery: cert transparency · DNS · IP/ASN · RDAP · urlscan · JS · VirusTotal · Reverse IP · ThreatFox/OTX · Platform pivots","type":"info","stage":"INIT"})

    # Open a row in the self-tracking PDNS store. Every (domain, ip, source,
    # observed_at) the pipeline sees gets recorded under this scan_id so future
    # scans can compare and the diff engine has snapshots to compare against.
    try:
        scan_id = pdns_store.start_scan(seed)
        result["scan_id"] = scan_id
    except Exception as e:
        scan_id = ""
        yield sse("log", {"msg": f"INIT: self-tracking PDNS unavailable ({e}) — pipeline continues",
                          "type": "warn", "stage": "INIT"})

    # Emit the canonical registrable (eTLD+1) up front so the client can fold
    # later same-base subdomains into the DOMAIN FAMILY panel without
    # re-implementing the public suffix list in JS.
    seed_reg = registrable_domain(seed) if not is_ip else None
    yield sse("seedMeta", {"seed": seed, "registrable": seed_reg, "is_ip": is_ip})

    # ── S1: Cert Transparency (domain) / Reverse-IP domain discovery (IP) ──
    yield sse("stage",{"n":1,"state":"active"})
    certs = []
    target = seed  # registrable-domain pivot applied in domain branch below
    if is_ip:
        yield sse("log",{"msg":f"S1: IP seed — certificate transparency is domain-only, pivoting via reverse IP for {seed}","type":"live","stage":"S1"})
        try:
            hosted = set()
            # Source 1: HackerTarget reverse-IP (free, rate-limited).
            rev = await fetch_reverse_ip_lookup(seed)
            if rev.get("error"):
                yield sse("log",{"msg":f"S1: HackerTarget reverse IP — {rev['error']}","type":"warn","stage":"S1"})
            else:
                ht = rev.get("domains", [])
                hosted.update(ht)
                yield sse("log",{"msg":f"S1: HackerTarget → {len(ht)} domain(s)"
                                 + (f" — {rev.get('note')}" if not ht and rev.get('note') else ""),
                                 "type":"ok" if ht else "info","stage":"S1"})
            # Source 2: urlscan.io page.ip search (domains historically seen on the IP).
            us_domains = await fetch_domains_on_ip(seed)
            if us_domains:
                hosted.update(us_domains)
                yield sse("log",{"msg":f"S1: urlscan.io → {len(us_domains)} domain(s) seen on {seed}","type":"ok","stage":"S1"})
            else:
                yield sse("log",{"msg":"S1: urlscan.io → no domains seen on this IP","type":"info","stage":"S1"})

            result["domains"] = [{"name": d, "source": "reverse_ip",
                                  "flag": ("NEIBU" if str(d).startswith("neibu") else None),
                                  "entropy": round(shannon_entropy(str(d).split(".")[0]), 2)}
                                 for d in sorted(hosted)[:100]]
            yield sse("log",{"msg":f"S1: {len(result['domains'])} unique domain(s) hosted on {seed}",
                             "type":"ok" if result["domains"] else "warn","stage":"S1"})
            yield sse("domains",{"domains":result["domains"],"source":"reverse_ip"})

            # Cluster enrichment: an IP has no certs/registration of its own, but its
            # hosted domains do. Look up certificate transparency + RDAP for a bounded
            # sample so the cert-issuance timeline and registrar-concentration panels
            # reflect the cluster (this is why a bare IP otherwise shows "no certs").
            sample = [d["name"] for d in result["domains"][:8]]
            if sample:
                yield sse("log",{"msg":f"S1: Enriching {len(sample)} hosted domain(s) with certificate transparency + registration","type":"live","stage":"S1"})
                # Use all enabled CT sources (certspotter/certkit are fast; crt.sh has the
                # best coverage for obscure TLDs) but cap each lookup so one slow/flaky
                # crt.sh query can't stall the whole batch. Run the sample concurrently.
                sem = asyncio.Semaphore(8)
                async def _certs_for(dom):
                    async with sem:
                        try: return await asyncio.wait_for(fetch_crtsh(dom, ct_sources), timeout=25)
                        except Exception: return []
                async def _reg_for(dom):
                    async with sem:
                        try:
                            s = await asyncio.wait_for(fetch_domain_registration(dom), timeout=18)
                            reg = s.get("registrar", "?")
                            return reg if reg not in ("?", "(not registered)") else None
                        except Exception:
                            return None
                cert_lists = await asyncio.gather(*[_certs_for(d) for d in sample])
                for cl in cert_lists: certs.extend(cl)
                result["certs"] = certs
                if certs:
                    yield sse("log",{"msg":f"S1: {len(certs)} certificate(s) found across the hosted-domain cluster","type":"ok","stage":"S1"})
                else:
                    yield sse("log",{"msg":"S1: 0 certs across the cluster — these domains have minimal certificate-transparency presence (likely HTTP-only or brand-new). This is itself a signal.","type":"warn","stage":"S1"})
                # Cert issuance timeline across the cluster
                result["cert_timeline"] = await fetch_cert_timeline(seed, certs)
                if result["cert_timeline"]:
                    months = Counter(c["month"] for c in result["cert_timeline"])
                    peak = max(months, key=months.get)
                    yield sse("certTimeline",{"timeline":result["cert_timeline"],"months":dict(months),"peak_month":peak,"peak_count":months[peak]})
                # Registrar concentration across the cluster — surface the top
                # registrar as a single log line; the dedicated panel was retired
                # along with the threat-score chrome.
                regs = await asyncio.gather(*[_reg_for(d) for d in sample])
                reg_counts = Counter(r for r in regs if r and r != "?")
                if reg_counts:
                    scam = ("gname","nicenic","west.cn","bizcn","hichina")
                    top_name, top_count = reg_counts.most_common(1)[0]
                    flagged = any(s in top_name.lower() for s in scam)
                    yield sse("log",{"msg":f"S1: Registrar concentration — {top_name} hosts {top_count}/{len(sample)} sampled domains",
                                     "type":"err" if flagged else "ok","stage":"S1"})
        except Exception as e:
            yield sse("log",{"msg":f"S1: Reverse IP lookup failed — {e}","type":"warn","stage":"S1"})
        for chip_id in ("crtsh","certspotter","certkit"):
            yield sse("chip",{"id":chip_id,"state":"pend"})
    else:
      # Pivot to the registered domain (eTLD+1) before querying crt.sh.
      # If the user pastes a deep random subdomain like liizlfb.bet30bet.com,
      # looking up `%.liizlfb.bet30bet.com` returns certs only for that one
      # exact host — missing the entire phishing cluster under bet30bet.com.
      # The registrable domain gives a full wildcard search.
      sld = registrable_domain(seed)
      if sld and sld != seed:
        yield sse("log",{"msg":f"S1: Pivot — {seed} → {sld} (registrable domain for crt.sh wildcard)","type":"live","stage":"S1"})
        target = sld
      else:
        target = seed
      yield sse("log",{"msg":f"S1: crt.sh wildcard query for %.{target}","type":"live","stage":"S1"})
      try:
        certs = await fetch_crtsh(target, ct_sources)
        # Identify which CT source actually answered, for an accurate log + chip state.
        src = (certs[0].get("_source") if certs else None) or "crtsh"
        src_label = {"crtsh":"crt.sh","certspotter":"certspotter","certkit":"certkit.io",
                     "censys":"censys","scantower":"scantower","cloudflare":"cloudflare"}.get(src, src)
        result["domains"] = extract_domains_from_certs(certs, seed)
        yield sse("log",{"msg":f"S1: {len(certs)} certs via {src_label} → {len(result['domains'])} domains","type":"ok","stage":"S1"})
        neibu = [d for d in result["domains"] if d.get("flag")=="NEIBU"]
        if neibu: yield sse("log",{"msg":f"S1: {len(neibu)} NEIBU (内部) admin portals flagged — Chinese admin panel tell","type":"err","stage":"S1"})
        yield sse("domains",{"domains":result["domains"],"source":src})
        # Light only the chip for the source that actually answered.
        for chip_id in ("crtsh","certspotter","certkit"):
            yield sse("chip",{"id":chip_id,"state":"live" if src==chip_id else "pend"})
        # Build cert timeline
        result["cert_timeline"] = await fetch_cert_timeline(seed, certs)
        if result["cert_timeline"]:
            months = Counter(c["month"] for c in result["cert_timeline"])
            peak = max(months, key=months.get)
            yield sse("certTimeline",{"timeline":result["cert_timeline"],"months":dict(months),"peak_month":peak,"peak_count":months[peak]})
            yield sse("log",{"msg":f"S1: Cert timeline built — {len(result['cert_timeline'])} issuances, peak: {peak} ({months[peak]} certs)","type":"ok","stage":"S1"})

            # Build infrastructure timeline
            if feat("timeline"):
                # Extract IP history from certificates for infrastructure tracking
                ip_history = []
                for cert in certs:
                    # Extract potential IPs from certificate data
                    # This is a simplified implementation - real implementation would
                    # extract from certificate transparency logs
                    if cert.get("name_value"):
                        ip_history.append({
                            "ip": "127.0.0.1",  # Placeholder
                            "last_resolved": cert.get("not_before", ""),
                            "source": "cert_transparency"
                        })

                result["infrastructure_timeline"] = await fetch_infrastructure_timeline(seed, ip_history)
                if result["infrastructure_timeline"].get("total_movements", 0) > 0:
                    yield sse("infraTimeline",{"timeline":result["infrastructure_timeline"]})
                    yield sse("log",{"msg":f"S1: Infra timeline built — {result['infrastructure_timeline']['total_movements']} provider changes detected","type":"ok","stage":"S1"})
            else:
                yield sse("log",{"msg":"S1: Infrastructure timeline disabled in settings","type":"info","stage":"S1"})
      except Exception as e:
        yield sse("log",{"msg":f"S1: CT unavailable — {e}","type":"warn","stage":"S1"})
        yield sse("chip",{"id":"crtsh","state":"fail"})
        yield sse("chip",{"id":"certspotter","state":"fail"})
        yield sse("corsNote",{"msg":"CT sources unavailable — no domains found. Retry in a few minutes or check the enabled CT sources in Settings."})
    yield sse("stage",{"n":1,"state":"done"})

    # ── S2: DNS ──
    yield sse("stage",{"n":2,"state":"active"})
    dns_records = []
    if is_ip:
        # An IP has no A/MX/NS records of its own — enrich the seed IP directly.
        ips = [seed]
        yield sse("log",{"msg":f"S2: IP seed — DNS record lookup skipped; enriching {seed} directly","type":"info","stage":"S2"})
        yield sse("chip",{"id":"dns","state":"pend"})
        yield sse("stage",{"n":2,"state":"done"})
    else:
      # Query DNS for BOTH the user-supplied seed (may resolve to specific phishing
      # IPs) AND the registrable domain (for MX/NS/CNAME/zone records). Deduplicate
      # across the two queries. A random subdomain like liizlfb.bet30bet.com often
      # has its own A record pointing to the phishing server, while bet30bet.com has
      # the full MX/NS/CNAME infrastructure.
      dns_queries = {seed}
      if target != seed:
        dns_queries.add(target)
      seen_rr = set()
      for qname in dns_queries:
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
          try:
              res = await fetch_dns(qname, rtype)
              if res.get("Answer"):
                  for a in res["Answer"]:
                      key = (rtype, a["data"])
                      if key in seen_rr: continue
                      seen_rr.add(key)
                      result["dns"].setdefault(rtype, []).append(a)
                      dns_records.append({"type":rtype,"value":a["data"],"ttl":a["TTL"],"source":qname})
                      yield sse("dnsRecord",{"type":rtype,"value":a["data"],"ttl":a["TTL"],"source":qname})
          except Exception:
              pass
      yield sse("chip",{"id":"dns","state":"live"})
      yield sse("log",{"msg":f"S2: {len(dns_records)} DNS records resolved ({' + '.join(sorted(dns_queries))})","type":"ok","stage":"S2"})
      ips = [a["data"] for a in result["dns"].get("A",[]) if validate_ip(a["data"])]
      if ips: yield sse("log",{"msg":f"S2: A records: {', '.join(ips[:6])}{' +{} more'.format(len(ips)-6) if len(ips)>6 else ''}","type":"ok","stage":"S2"})
      else:   yield sse("log",{"msg":"S2: No A records — behind CDN or domain parked","type":"warn","stage":"S2"})
      yield sse("stage",{"n":2,"state":"done"})

    # ── S3: IP Intel ──
    yield sse("stage",{"n":3,"state":"active"})
    # IP → domain mapping so the UI can show which domain each IP serves. For an IP seed
    # the seed IP serves the discovered hosted domains; for a domain the seed resolves
    # to these IPs.
    hosted_names = [d["name"] for d in result["domains"]]
    for ip in ips[:5]:
        try:
            await asyncio.sleep(0.3)
            info = await fetch_ipinfo(ip)
            result["ip_results"].append(info)
            if is_ip:
                ip_domains = hosted_names
            else:
                ip_domains = [seed]
            domain_count = len(ip_domains)
            hosting = classify_ip_hosting(info, domain_count)
            info["hosting_class"] = hosting
            yield sse("ipInfo",{"ip":ip,"info":info,"domains":ip_domains[:200],"domain_count":domain_count,"hosting_class":hosting})
            yield sse("log",{"msg":f"S3: {ip} → {info.get('isp','?')} | {info.get('as','?')} | {info.get('country','?')}","type":"ok","stage":"S3"})
            isp = info.get("isp","").lower()
            if hosting["shared_hosting"]:
                result["shared_hosting"] = {"ip": ip, **hosting}
                yield sse("sharedHosting",{"ip":ip,**hosting})
                yield sse("log",{"msg":f"S3: {hosting['verdict']}","type":"info","stage":"S3"})
            elif any(kw in isp for kw in ("alibaba","tencent","chinanet")):
                yield sse("log",{"msg":f"S3: Chinese cloud provider detected — {info['isp']}","type":"err","stage":"S3"})
            elif hosting["is_cdn"]:
                yield sse("log",{"msg":f"S3: {hosting['verdict']}","type":"warn","stage":"S3"})
            elif info.get("hosting"):
                yield sse("log",{"msg":f"S3: Datacenter/hosting IP ({info.get('as','?')})","type":"warn","stage":"S3"})
        except Exception as e:
            yield sse("log",{"msg":f"S3: {ip} enrichment failed — {e}","type":"warn","stage":"S3"})
    yield sse("chip",{"id":"ipapi","state":"live" if result["ip_results"] else "fail"})
    yield sse("stage",{"n":3,"state":"done"})

    # ── S4: ASN Intelligence ──
    yield sse("stage",{"n":4,"state":"active"})
    if not feat("asn_intel"):
        yield sse("log",{"msg":"S4: ASN intelligence disabled in settings","type":"info","stage":"S4"})
        yield sse("chip",{"id":"asn","state":"pend"})
    elif not result["ip_results"]:
        yield sse("log",{"msg":"S4: No IPs to analyze for ASN intelligence","type":"info","stage":"S4"})
        yield sse("chip",{"id":"asn","state":"pend"})
    else:
        yield sse("log",{"msg":"S4: Gathering ASN intelligence for resolved IPs","type":"live","stage":"S4"})
        # Get ASN data for all resolved IPs
        ip_list = [info["query"] for info in result["ip_results"]]
        try:
            # Perform bulk ASN lookups
            asn_data_list = await bulk_lookup_asns(ip_list)
            result["asn_data"] = asn_data_list
            
            # Generate ASN intelligence report
            asn_report = generate_asn_report(ip_list, asn_data_list)
            result["asn_report"] = asn_report
            
            # Log ASN intelligence findings
            yield sse("log",{"msg":f"S4: Analyzed {len(ip_list)} IP addresses across {asn_report['summary']['unique_asns']} unique ASNs","type":"ok","stage":"S4"})
            
            # Report suspicious ASNs if found
            if asn_report["summary"]["suspicious_asns_count"] > 0:
                yield sse("log",{"msg":f"S4: !! SUSPICIOUS ASN DETECTED: {asn_report['summary']['suspicious_asns_count']} known malicious ASNs found","type":"err","stage":"S4"})
                for asn in asn_report["suspicious_asns"][:3]:  # Show first 3
                    yield sse("log",{"msg":f"S4: Suspicious ASN: AS{asn}","type":"err","stage":"S4"})
            
            # Report datacenter IPs if found
            if asn_report["summary"]["datacenter_ips"] > 0:
                yield sse("log",{"msg":f"S4: Datacenter infrastructure detected: {asn_report['summary']['datacenter_ips']} IPs","type":"warn","stage":"S4"})
            
            # Report hosting patterns if found
            if asn_report["hosting_patterns"]:
                top_pattern = asn_report["hosting_patterns"][0]
                yield sse("log",{"msg":f"S4: Hosting pattern detected: AS{top_pattern['asn']} appears in {top_pattern['percentage']}% of IPs","type":"warn","stage":"S4"})
            
            yield sse("asnData",{"data":asn_data_list,"report":asn_report})
            yield sse("chip",{"id":"asn","state":"live"})
            
        except Exception as e:
            yield sse("log",{"msg":f"S4: ASN intelligence failed — {e}","type":"warn","stage":"S4"})
            yield sse("chip",{"id":"asn","state":"fail"})
    yield sse("stage",{"n":4,"state":"done"})

    # ── S5: Registration (RDAP → passive WHOIS fallback) ──
    yield sse("stage",{"n":5,"state":"active"})
    if is_ip:
        yield sse("log",{"msg":"S5: IP seed — domain registration N/A (see registrar concentration)","type":"info","stage":"S5"})
        yield sse("chip",{"id":"rdap","state":"pend"})
    else:
      yield sse("log",{"msg":f"S5: Registration lookup for {target} (RDAP, then public WHOIS)","type":"live","stage":"S5"})
      try:
        summary = await fetch_domain_registration(target)
        result["rdap"] = summary
        yield sse("rdap",{"summary":summary})
        yield sse("chip",{"id":"rdap","state":"live"})
        created_short = summary["created"][:10] if summary["created"]!="?" else "?"
        src = summary.get("source","rdap").upper()
        yield sse("log",{"msg":f"S5: [{src}] {summary['registrar']} | Created: {created_short} | {summary['status']}","type":"ok","stage":"S5"})
        scam_primary = ("gname","nicenic","west.cn","bizcn","hichina")
        if any(r in summary["registrar"].lower() for r in scam_primary):
            yield sse("log",{"msg":f"S5: REGISTRAR FLAGGED: {summary['registrar']} — primary scam-kit registrar","type":"err","stage":"S5"})
        if created_short != "?":
            try:
                age = (datetime.now(timezone.utc)-datetime.fromisoformat(summary["created"].replace("Z","+00:00"))).days
                if age < 90: yield sse("log",{"msg":f"S5: FRESH DOMAIN — {age} days old. High risk.","type":"err","stage":"S5"})
            except Exception: pass
      except Exception as e:
        yield sse("chip",{"id":"rdap","state":"fail"})
        yield sse("log",{"msg":f"S5: Registration unavailable (RDAP + WHOIS) — {e}","type":"warn","stage":"S5"})
    yield sse("stage",{"n":5,"state":"done"})

    # ── S6: urlscan.io ──
    yield sse("stage",{"n":6,"state":"active"})
    yield sse("log",{"msg":f"S6: urlscan.io corroboration — scanning for {seed}","type":"live","stage":"S6"})
    result["urlscan"] = await fetch_urlscan(seed)
    us = result["urlscan"]
    if us.get("total",0) > 0:
        yield sse("log",{"msg":f"S6: urlscan found {us['total']} scans · {len(us['unique_ips'])} unique IPs · {len(us.get('unique_asns',[]))} ASNs","type":"ok","stage":"S6"})
        yield sse("urlscan",{"data":us})
        yield sse("chip",{"id":"urlscan","state":"live"})
    else:
        yield sse("log",{"msg":"S6: No urlscan.io history — domain may be new or not yet scanned","type":"info","stage":"S6"})
        yield sse("chip",{"id":"urlscan","state":"pend"})
    yield sse("stage",{"n":6,"state":"done"})

    # Sort the cluster by label entropy so machine-generated names surface to
    # the top of the DOMAIN FAMILY panel — purely a display ordering, not a
    # threat verdict.
    result["domains"] = sorted(result["domains"], key=lambda d: d.get("entropy", 0), reverse=True)
    yield sse("domains",{"domains":result["domains"],"source":"sorted_by_entropy"})

    # ── S7: Shodan Intelligence ──
    yield sse("stage",{"n":7,"state":"active"})
    yield sse("log",{"msg":"S7: Gathering Shodan intelligence for resolved IPs","type":"live","stage":"S7"})
    
    # Get Shodan data for the first IP we found
    shodan_results = []
    for ip in ips[:3]:  # Check first 3 IPs
        try:
            if SHODAN_API_KEY:
                shodan_data = await fetch_shodan_data(ip, SHODAN_API_KEY)
                shodan_results.append(shodan_data)
                result["shodan"] = shodan_data  # Store for scoring
                
                if not shodan_data.get("error"):
                    open_ports = shodan_data.get("open_ports", [])
                    if open_ports:
                        yield sse("log",{"msg":f"S7: Shodan found {len(open_ports)} open ports on {ip}: {open_ports}","type":"ok","stage":"S7"})
                        # Check for risky ports
                        risky_ports = [21, 22, 23, 25, 53, 110, 143, 445, 1433, 3306, 3389, 5432, 6379, 27017]
                        found_risky = [port for port in open_ports if port in risky_ports]
                        if found_risky:
                            yield sse("log",{"msg":f"S7: !! RISKY PORTS DETECTED: {found_risky}","type":"err","stage":"S7"})
                    else:
                        yield sse("log",{"msg":f"S7: Shodan check complete for {ip} - no open ports found","type":"ok","stage":"S7"})
                else:
                    yield sse("log",{"msg":f"S7: Shodan error for {ip}: {shodan_data.get('error')}","type":"warn","stage":"S7"})
            else:
                yield sse("log",{"msg":"S7: Shodan API key not configured - skipping","type":"info","stage":"S7"})
                break
        except Exception as e:
            yield sse("log",{"msg":f"S7: Shodan check failed for {ip}: {str(e)}","type":"warn","stage":"S7"})

    if shodan_results:
        yield sse("chip",{"id":"shodan","state":"live"})
    else:
        yield sse("chip",{"id":"shodan","state":"fail"})
    # Keep the per-IP list around — S19 (pivot stage) extracts JARMs from it.
    result["shodan_per_ip"] = shodan_results
    yield sse("stage",{"n":7,"state":"done"})

    # ── S8: VirusTotal Passive DNS ──
    yield sse("stage",{"n":8,"state":"active"})
    yield sse("log",{"msg":"S8: Checking VirusTotal passive DNS history","type":"live","stage":"S8"})
    
    try:
        if VIRUSTOTAL_API_KEY:
            vt_data = await fetch_virustotal_passive_dns(seed, VIRUSTOTAL_API_KEY)
            result["virustotal"] = vt_data  # Store for scoring

            if not vt_data.get("error"):
                if is_ip:
                    # IP seed → VT returns historical domains that resolved to this IP.
                    domain_history = vt_data.get("domain_history", [])
                    if domain_history:
                        yield sse("log",{"msg":f"S8: VirusTotal found {len(domain_history)} historical domains for {seed}","type":"ok","stage":"S8"})
                        for entry in domain_history:
                            yield sse("log",{"msg":f"S8: Historical domain: {entry['domain']} (last resolved: {entry['last_resolved']})","type":"ok","stage":"S8"})
                    else:
                        yield sse("log",{"msg":"S8: VirusTotal found no historical domains","type":"info","stage":"S8"})
                else:
                    ip_history = vt_data.get("ip_history", [])
                    if ip_history:
                        yield sse("log",{"msg":f"S8: VirusTotal found {len(ip_history)} historical IP addresses","type":"ok","stage":"S8"})
                        # Stream every historical IP so the analyst sees the full pivot
                        # surface in the log, not just the most recent few.
                        for ip_entry in ip_history:
                            yield sse("log",{"msg":f"S8: Historical IP: {ip_entry['ip']} (last resolved: {ip_entry['last_resolved']})","type":"ok","stage":"S8"})
                    else:
                        yield sse("log",{"msg":"S8: VirusTotal found no historical IP addresses","type":"info","stage":"S8"})
            else:
                yield sse("log",{"msg":f"S8: VirusTotal error: {vt_data.get('error')}","type":"warn","stage":"S8"})
        else:
            yield sse("log",{"msg":"S8: VirusTotal API key not configured - skipping","type":"info","stage":"S8"})
    except Exception as e:
        yield sse("log",{"msg":f"S8: VirusTotal check failed: {str(e)}","type":"warn","stage":"S8"})

    # S8 continued: VT reputation — vendor verdict counts + reputation score.
    # Surfaces critical findings (5+ malicious verdicts or reputation <= -50)
    # so they bubble into the findings panel rather than only the raw event.
    if VIRUSTOTAL_API_KEY:
        try:
            vt_rep = await fetch_virustotal_reputation(seed, VIRUSTOTAL_API_KEY)
            result["virustotal_reputation"] = vt_rep
            if vt_rep.get("error"):
                yield sse("log",{"msg":f"S8: VT reputation: {vt_rep['error']}","type":"warn","stage":"S8"})
            elif vt_rep.get("not_found"):
                yield sse("log",{"msg":f"S8: VT reputation: {seed} not present in VT corpus","type":"info","stage":"S8"})
            else:
                yield sse("log",{"msg":f"S8: VT reputation: verdict={vt_rep.get('verdict')} malicious={vt_rep.get('malicious')}/{vt_rep.get('total')} reputation={vt_rep.get('reputation')}","type":"info","stage":"S8"})
                for f in _findings_from_vt(vt_rep, context_seed=seed):
                    yield sse("finding", f)
            yield sse("vtReputation", vt_rep)
        except Exception as e:
            yield sse("log",{"msg":f"S8: VT reputation failed: {str(e)}","type":"warn","stage":"S8"})

    yield sse("chip",{"id":"virustotal","state":"live" if VIRUSTOTAL_API_KEY and not result.get('virustotal', {}).get('error') else "fail"})
    yield sse("stage",{"n":8,"state":"done"})

    # Merge historical IPs from VT passive DNS + URLScan + current DNS A records
    # into a single event so the frontend can show the full IP history of the
    # domain — the core of the infrastructure-pivot workflow.
    hist_list = []  # initialized empty so the S9 stage below can read it unconditionally
    if not is_ip:
      hist_ips = {}  # ip -> {sources, first_seen, last_seen}
      def _add_hist(ip, source, seen_ts=""):
        # Sources hand back timestamps in different types — VT exposes
        # `attributes.date` as a Unix-epoch int, OTX returns ISO-8601 strings.
        # Mixing the two in a `<`/`>` comparison raises TypeError. Coerce to
        # str at the boundary so the aggregator stays type-clean.
        seen_ts = str(seen_ts) if seen_ts not in (None, "") else ""
        e = hist_ips.setdefault(ip, {"sources": set(), "first_seen": seen_ts, "last_seen": seen_ts})
        # If the entry was previously seeded with a non-str (older bug), reset.
        if not isinstance(e["first_seen"], str): e["first_seen"] = str(e["first_seen"] or "")
        if not isinstance(e["last_seen"], str): e["last_seen"] = str(e["last_seen"] or "")
        e["sources"].add(source)
        if seen_ts:
          if not e["first_seen"] or seen_ts < e["first_seen"]: e["first_seen"] = seen_ts
          if not e["last_seen"] or seen_ts > e["last_seen"]: e["last_seen"] = seen_ts
      # Source 1: VT passive DNS
      vt = result.get("virustotal", {})
      for entry in vt.get("ip_history", []):
        ip = entry.get("ip")
        if ip and validate_ip(ip):
          _add_hist(ip, "virustotal", entry.get("last_resolved", ""))
      # Source 2: URLScan (already collected in result["urlscan"])
      us = result.get("urlscan", {})
      for ip in us.get("unique_ips", []):
        _add_hist(ip, "urlscan")
      # Source 3: current A records (already in ips list from DNS stage)
      for ip in ips:
        _add_hist(ip, "dns_current")
      # Source 4: OTX domain passive-DNS — fills `last_seen` timestamps for IPs
      # VT didn't carry (Universal-SSL Cloudflare hosts, etc.).
      if ALIENVAULT_API_KEY:
        try:
          otx_pdns = await fetch_otx_domain_passive_dns(seed, ALIENVAULT_API_KEY)
          result["otx_domain_pdns"] = otx_pdns
          if otx_pdns.get("error"):
            yield sse("log", {"msg": f"S9: OTX domain pDNS: {otx_pdns['error']}", "type": "warn", "stage": "S9"})
          else:
            for rec in otx_pdns.get("records", []):
              _add_hist(rec["ip"], "otx_pdns", rec.get("last") or rec.get("first") or "")
            yield sse("log", {"msg": f"S9: OTX domain pDNS → {otx_pdns.get('count', 0)} historical observation(s) with timestamps", "type": "info", "stage": "S9"})
        except Exception as e:
          yield sse("log", {"msg": f"S9: OTX domain pDNS failed: {e}", "type": "warn", "stage": "S9"})
      # Source 5: CIRCL.lu passive DNS — EU sensor coverage, historical A/AAAA
      # with timestamps. Skipped silently if no credentials are configured.
      if CIRCL_PDNS_USERNAME and CIRCL_PDNS_PASSWORD:
        try:
          circl = await fetch_circl_pdns(seed, CIRCL_PDNS_USERNAME, CIRCL_PDNS_PASSWORD)
          result["circl_pdns"] = circl
          if circl.get("error"):
            yield sse("log", {"msg": f"S9: CIRCL PDNS: {circl['error']}", "type": "warn", "stage": "S9"})
          else:
            for rec in circl.get("records", []):
              _add_hist(rec["ip"], "circl_pdns", rec.get("last") or rec.get("first") or "")
            yield sse("log", {"msg": f"S9: CIRCL PDNS → {circl.get('count', 0)} historical observation(s)",
                              "type": "info", "stage": "S9"})
        except Exception as e:
          yield sse("log", {"msg": f"S9: CIRCL PDNS failed: {e}", "type": "warn", "stage": "S9"})
      # Source 6: Mnemonic Argus passive DNS — Nordic/EU visibility.
      if MNEMONIC_API_KEY:
        try:
          mnem = await fetch_mnemonic_pdns(seed, MNEMONIC_API_KEY)
          result["mnemonic_pdns"] = mnem
          if mnem.get("error"):
            yield sse("log", {"msg": f"S9: Mnemonic PDNS: {mnem['error']}", "type": "warn", "stage": "S9"})
          else:
            for rec in mnem.get("records", []):
              _add_hist(rec["ip"], "mnemonic_pdns", rec.get("last") or rec.get("first") or "")
            yield sse("log", {"msg": f"S9: Mnemonic PDNS → {mnem.get('count', 0)} historical observation(s)",
                              "type": "info", "stage": "S9"})
        except Exception as e:
          yield sse("log", {"msg": f"S9: Mnemonic PDNS failed: {e}", "type": "warn", "stage": "S9"})
      # Source 7: SELF-TRACKING — our own SQLite store of past observations.
      # Surfaces "we ourselves saw this IP on date X" alongside external sources,
      # filling gaps when external feeds drop a domain or never carried it.
      try:
        own = pdns_store.query_domain_history(seed)
        for rec in own:
          _add_hist(rec["ip"], "self_tracking", rec.get("last_observed") or rec.get("first_observed") or "")
        if own:
          yield sse("log", {"msg": f"S9: Self-tracking PDNS → {len(own)} IP(s) from prior scans of this seed",
                            "type": "info", "stage": "S9"})
      except Exception as e:
        yield sse("log", {"msg": f"S9: Self-tracking PDNS read failed: {e}", "type": "warn", "stage": "S9"})

      # Persist every (ip, source, observed_at) tuple from this run into the
      # self-tracking store. Idempotent on the UNIQUE constraint, so re-running
      # the same scan adds zero new rows.
      if scan_id and hist_ips:
        try:
          obs_rows = []
          for ip, v in hist_ips.items():
            for src in v["sources"]:
              obs_rows.append({
                "ip": ip,
                "source": src,
                "observed_at": v["last_seen"] or v["first_seen"] or "",
                "record_type": "A",
              })
          inserted = pdns_store.record_observations(scan_id, seed, obs_rows)
          if inserted:
            yield sse("log", {"msg": f"S9: Self-tracking PDNS recorded {inserted} new observation(s)",
                              "type": "ok", "stage": "S9"})
        except Exception as e:
          yield sse("log", {"msg": f"S9: Self-tracking PDNS write failed: {e}", "type": "warn", "stage": "S9"})

      if hist_ips:
        # Convert sets to lists for JSON serialization
        hist_list = [{"ip": k, "sources": sorted(v["sources"]), "first_seen": v["first_seen"], "last_seen": v["last_seen"]}
                     for k, v in sorted(hist_ips.items(), key=lambda x: -len(x[1]["sources"]))]
        current = set(ips)
        for h in hist_list:
          h["current"] = h["ip"] in current
        yield sse("historicalIps", {"ips": hist_list, "total": len(hist_list), "current_count": len(ips)})
        yield sse("log", {"msg": f"S9: {len(hist_list)} historical IPs across {len(set(s for h in hist_list for s in h['sources']))} sources — {len(ips)} currently active", "type": "ok", "stage": "S9"})

    # ── S9: abuse.ch ThreatFox + OTX passive-DNS cross-reference ──
    # The existing S13 IOC correlation only does exact-match lookups on the seed,
    # which misses sister IOCs (e.g. *.bet30bet.com listings co-hosted on the same
    # IPs). ThreatFox's search_ioc does substring matching on the value field, so
    # we query the seed AND each resolved IP. OTX's IP passive_dns rounds out the
    # picture with historical sister domains seen by the OTX community.
    yield sse("stage", {"n":9, "state": "active"})
    yield sse("log", {"msg": "S9: Cross-referencing abuse.ch ThreatFox + AlienVault OTX for sister IOCs", "type": "live", "stage":"S9"})
    # Build the IP set to query — current resolved IPs plus any historical IPs
    # we just merged. Dedupe and cap so a long history doesn't burn the budget.
    if not is_ip:
        ip_pool = list(dict.fromkeys(list(ips) + [h["ip"] for h in hist_list]))
    else:
        ip_pool = [seed]
    # ThreatFox's `search_ioc` does substring matching on the IOC value field.
    # Querying only the exact seed (e.g. liizlfb.bet30bet.com) finds itself but
    # misses sister subdomains (eltyalg.bet30bet.com, ojxpecw.bet30bet.com, …).
    # Adding the registrable domain as a second search term substring-matches
    # every *.bet30bet.com listing in one shot.
    if is_ip:
        threatfox_seed_terms: list = []
    else:
        threatfox_seed_terms = [seed]
        reg = registrable_domain(seed)
        if reg and reg != seed:
            threatfox_seed_terms.append(reg)

    # 1. ThreatFox — best-effort even without a key (some queries still work)
    if not is_ip and len(threatfox_seed_terms) > 1:
        yield sse("log", {"msg": f"S9: ThreatFox seed-side terms: exact={threatfox_seed_terms[0]} + brand={threatfox_seed_terms[1]} (substring-match for sister subdomains)", "type": "info", "stage":"S9"})
    try:
        tf_data = await fetch_threatfox(threatfox_seed_terms, ip_pool, ABUSECH_API_KEY)
        result["threatfox"] = tf_data
        if tf_data.get("error") and not tf_data.get("matches"):
            yield sse("log", {"msg": f"S9: ThreatFox: {tf_data['error']}", "type": "warn", "stage":"S9"})
        else:
            n = len(tf_data.get("matches") or [])
            sh, ih = tf_data.get("seed_hits", 0), tf_data.get("ip_hits", 0)
            if n:
                yield sse("log", {"msg": f"S9: ThreatFox matched {n} IOC{'s' if n!=1 else ''} ({sh} via seed, {ih} via IPs)", "type": "warn", "stage":"S9"})
                # Log the top few so they show in the live stream
                for row in (tf_data["matches"] or [])[:8]:
                    fam = row.get("malware") or row.get("threat_type") or "?"
                    yield sse("log", {"msg": f"S9: ThreatFox: {row.get('ioc')}  [{row.get('ioc_type','?')}]  {fam}  last={row.get('last_seen') or '?'}", "type": "warn", "stage":"S9"})
                # Elevate named-family / threat-type matches as structured findings
                # so they render prominently above the log instead of scrolling past.
                for f in _findings_from_threatfox(tf_data, context_seed=seed):
                    yield sse("finding", f)
            else:
                yield sse("log", {"msg": "S9: ThreatFox returned no matches for seed or resolved IPs", "type": "info", "stage":"S9"})
            yield sse("threatfox", tf_data)
    except Exception as e:
        yield sse("log", {"msg": f"S9: ThreatFox query failed: {e}", "type": "warn", "stage":"S9"})

    # 2. OTX IP passive-DNS — surfaces sister domains observed on each IP
    if not is_ip and ALIENVAULT_API_KEY:
        try:
            otx_sister = await fetch_otx_ip_passive_dns(ip_pool, ALIENVAULT_API_KEY)
            result["otx_sister"] = otx_sister
            if otx_sister.get("error") and not otx_sister.get("flat"):
                yield sse("log", {"msg": f"S9: OTX passive-DNS: {otx_sister['error']}", "type": "warn", "stage":"S9"})
            else:
                flat = otx_sister.get("flat") or []
                seed_norm = (seed or "").lower().strip(".")
                # Filter out the seed itself
                flat = [r for r in flat if r["hostname"] != seed_norm]
                otx_sister["flat"] = flat
                if flat:
                    yield sse("log", {"msg": f"S9: OTX passive-DNS surfaced {len(flat)} sister domain{'s' if len(flat)!=1 else ''} across {len(ip_pool)} IP{'s' if len(ip_pool)!=1 else ''}", "type": "warn", "stage":"S9"})
                    for row in flat[:6]:
                        yield sse("log", {"msg": f"S9: OTX sister: {row['hostname']}  on {','.join(row['ips'])}  last={row.get('last') or '?'}", "type": "warn", "stage":"S9"})
                else:
                    yield sse("log", {"msg": "S9: OTX passive-DNS returned no additional sister domains", "type": "info", "stage":"S9"})
                yield sse("otxSister", otx_sister)
        except Exception as e:
            yield sse("log", {"msg": f"S9: OTX passive-DNS failed: {e}", "type": "warn", "stage":"S9"})
    elif not ALIENVAULT_API_KEY:
        yield sse("log", {"msg": "S9: OTX passive-DNS skipped — AlienVault OTX API key not configured", "type": "info", "stage":"S9"})

    # S9 continued: OTX pulse memberships — surfaces named malware families
    # and attacker-tooling tags (RAT/ransomware/loader/...) that the passive-DNS
    # call doesn't carry. Queries seed + up to 8 IPs in parallel.
    if ALIENVAULT_API_KEY:
        try:
            otx_seeds = [seed] + [ip for ip in (ip_pool or [])[:7] if ip != seed]
            otx_general = await fetch_otx_general(otx_seeds, ALIENVAULT_API_KEY)
            result["otx_general"] = otx_general
            if otx_general.get("error") and not otx_general.get("per_seed"):
                yield sse("log", {"msg": f"S9: OTX pulses: {otx_general['error']}", "type": "warn", "stage":"S9"})
            else:
                total_pulses = sum(len(e.get("pulses") or []) for e in (otx_general.get("per_seed") or []))
                if total_pulses:
                    yield sse("log", {"msg": f"S9: OTX surfaced {total_pulses} pulse membership(s) across seed+IPs", "type": "info", "stage":"S9"})
                else:
                    yield sse("log", {"msg": "S9: OTX returned no pulse memberships for seed or IPs", "type": "info", "stage":"S9"})
                for f in _findings_from_otx_pulses(otx_general, context_seed=seed):
                    yield sse("finding", f)
            yield sse("otxGeneral", otx_general)
        except Exception as e:
            yield sse("log", {"msg": f"S9: OTX pulse lookup failed: {e}", "type": "warn", "stage":"S9"})

    yield sse("stage", {"n":9, "state": "done"})

    # ── S10: Platform pivots — favicon mmh3, body hash, tracker IDs, JARM, reverse-NS ──
    # The major pivoting platforms (Validin / Silent Push / Censys / Shodan /
    # DT Iris / Maltego) all key on the same handful of fingerprints. This
    # stage computes them seed-side and runs the corresponding reverse-pivots
    # against Shodan + Censys + HackerTarget.
    yield sse("stage", {"n":10, "state": "active"})
    yield sse("log", {"msg": "S10: Computing pivot fingerprints (favicon mmh3, body SHA-256, tracking IDs, JARM) in parallel", "type": "live", "stage":"S10"})

    # Build the nameserver list once so both the rev-NS call and any later
    # consumer see the same view.
    ns_list = []
    if not is_ip:
        for ns_entry in (result.get("rdap", {}) or {}).get("nameservers", []) or []:
            if isinstance(ns_entry, dict):
                name = ns_entry.get("ldhName") or ns_entry.get("name") or ""
            else:
                name = str(ns_entry)
            if name:
                ns_list.append(name.lower().strip("."))
        if not ns_list:
            for rec in (result.get("dns", {}) or {}).get("NS", []) or []:
                v = (rec.get("data") if isinstance(rec, dict) else str(rec)).strip(".").lower()
                if v:
                    ns_list.append(v)
        ns_list = list(dict.fromkeys(ns_list))

    # Phase 1: independent network work — seed fingerprint + reverse-NS run in
    # parallel. Sequential, these were ~5s + ~10s; together they're bounded by
    # the slower of the two. JARM extraction is CPU-only so it stays inline.
    fp: dict = {}
    ns_data: dict = {}
    if not is_ip:
        tasks = [fetch_seed_fingerprint(seed)]
        if ns_list:
            tasks.append(fetch_reverse_ns(ns_list))
        try:
            results_p1 = await asyncio.gather(*tasks, return_exceptions=True)
            fp_or_err = results_p1[0]
            if isinstance(fp_or_err, Exception):
                yield sse("log", {"msg": f"S10: Seed fingerprint failed: {fp_or_err}", "type": "warn", "stage":"S10"})
            else:
                fp = fp_or_err
                result["pivot_fingerprint"] = fp
                if fp.get("favicon_hash") is not None:
                    yield sse("log", {"msg": f"S10: Favicon mmh3 = {fp['favicon_hash']}  (md5={fp.get('favicon_md5','?')[:12]}…, {fp.get('favicon_bytes',0)}B from {fp.get('favicon_url','?')})", "type": "ok", "stage":"S10"})
                else:
                    yield sse("log", {"msg": "S10: Favicon not retrievable — skipping Shodan/Censys favicon pivot", "type": "info", "stage":"S10"})
                if fp.get("body_sha256"):
                    yield sse("log", {"msg": f"S10: Body SHA-256 = {fp['body_sha256'][:16]}…  normalized={fp.get('body_sha256_norm','')[:16]}…", "type": "ok", "stage":"S10"})
                if fp.get("tracking_ids"):
                    ids_summary = ", ".join(f"{t['label']}={t['value']}" for t in fp["tracking_ids"][:6])
                    yield sse("log", {"msg": f"S10: Tracking IDs ({len(fp['tracking_ids'])}): {ids_summary}", "type": "warn", "stage":"S10"})
                yield sse("contentFingerprint", fp)
            if ns_list:
                ns_or_err = results_p1[1]
                if isinstance(ns_or_err, Exception):
                    yield sse("log", {"msg": f"S10: Reverse-NS failed: {ns_or_err}", "type": "warn", "stage":"S10"})
                    yield sse("reverseNs", {"per_ns": [], "flat": [], "error": f"failed: {ns_or_err}"})
                else:
                    ns_data = ns_or_err
                    flat = ns_data.get("flat") or []
                    seed_norm = (seed or "").lower().strip(".")
                    flat = [r for r in flat if r["hostname"] != seed_norm]
                    ns_data["flat"] = flat
                    result["reverse_ns"] = ns_data
                    yield sse("log", {"msg": f"S10: Reverse-NS — {len(flat)} sister domain{'s' if len(flat)!=1 else ''} across {len(ns_list)} nameserver{'s' if len(ns_list)!=1 else ''}", "type": "warn" if flat else "info", "stage":"S10"})
                    for row in flat[:6]:
                        yield sse("log", {"msg": f"S10: Reverse-NS: {row['hostname']}  via {','.join(row['nameservers'])}", "type": "warn", "stage":"S10"})
                    yield sse("reverseNs", ns_data)
            else:
                yield sse("log", {"msg": "S10: Reverse-NS skipped — no nameservers identified for seed", "type": "info", "stage":"S10"})
        except Exception as e:
            yield sse("log", {"msg": f"S10: Phase-1 fan-out failed: {e}", "type": "warn", "stage":"S10"})

    # JARM extraction from Shodan data already fetched in S7 — CPU-only.
    # extract_jarms_from_shodan_results filters out the 62-char all-zero
    # sentinel Shodan stores when a probe got no usable TLS Server Hello,
    # so an empty result here means "no real fingerprint available".
    try:
        jarms = extract_jarms_from_shodan_results(result.get("shodan_per_ip") or [])
        # Count how many raw (pre-filter) JARM values Shodan reported, so we
        # can distinguish "Shodan saw the host but got no fingerprint" from
        # "we never asked Shodan / no IPs to ask about".
        raw_jarm_count = 0
        for entry in (result.get("shodan_per_ip") or []):
            raw_jarm_count += len(entry.get("jarms") or [])
        if jarms:
            result["jarms"] = jarms
            total_eps = sum(j.get("endpoint_count", 0) for j in jarms)
            yield sse("log", {"msg": f"S10: JARM fingerprints — {len(jarms)} distinct across {total_eps} endpoint(s)", "type": "warn", "stage":"S10"})
            for j in jarms[:6]:
                eps = j.get("endpoint_count", 0)
                ips = j.get("distinct_ips", 0)
                ep0 = (j.get("endpoints") or [{}])[0]
                yield sse("log", {"msg": f"S10: JARM {j['jarm']} — {eps} endpoint(s) across {ips} IP(s) (e.g. {ep0.get('ip','?')}:{ep0.get('port','?')})", "type": "ok", "stage":"S10"})
            yield sse("jarmPivot", {"jarms": jarms})
        elif raw_jarm_count:
            yield sse("log", {"msg": f"S10: Shodan returned {raw_jarm_count} JARM record(s) but all were the all-zero null sentinel — no usable fingerprint (host likely behind CDN / refused TLS probe)", "type": "info", "stage":"S10"})
            yield sse("jarmPivot", {"jarms": []})
    except Exception as e:
        yield sse("log", {"msg": f"S10: JARM extraction failed: {e}", "type": "warn", "stage":"S10"})

    # Phase 2: favicon-hash-dependent pivots — Shodan + Censys run in parallel
    # once we have the hash from phase 1.
    fav_hash = (fp or {}).get("favicon_hash")
    if not is_ip and fav_hash is not None:
        try:
            sh_piv, cs_piv = await asyncio.gather(
                shodan_favicon_pivot(fav_hash, SHODAN_API_KEY),
                censys_favicon_pivot(fav_hash, CENSYS_API_ID, CENSYS_API_SECRET),
                return_exceptions=False,
            )
            result["favicon_pivot_shodan"] = sh_piv
            result["favicon_pivot_censys"] = cs_piv
            # Shodan
            if sh_piv.get("error"):
                yield sse("log", {"msg": f"S10: Shodan favicon pivot: {sh_piv['error']}", "type": "info", "stage":"S10"})
            else:
                n = len(sh_piv.get("matches") or [])
                yield sse("log", {"msg": f"S10: Shodan favicon pivot — {sh_piv.get('total','?')} total hosts, returning {n}", "type": "warn" if n else "info", "stage":"S10"})
                for m in (sh_piv.get("matches") or [])[:6]:
                    hn = ",".join(m.get("hostnames") or []) or "—"
                    yield sse("log", {"msg": f"S10: Shodan match {m.get('ip')}:{m.get('port')}  {hn}  ({m.get('org') or '?'})", "type": "warn", "stage":"S10"})
            yield sse("faviconPivotShodan", sh_piv)
            # Censys
            if cs_piv.get("error"):
                yield sse("log", {"msg": f"S10: Censys favicon pivot: {cs_piv['error']}", "type": "info", "stage":"S10"})
            else:
                n = len(cs_piv.get("matches") or [])
                yield sse("log", {"msg": f"S10: Censys favicon pivot — {cs_piv.get('total','?')} total hosts, returning {n}", "type": "warn" if n else "info", "stage":"S10"})
                for m in (cs_piv.get("matches") or [])[:6]:
                    hn = ",".join(m.get("hostnames") or []) or "—"
                    yield sse("log", {"msg": f"S10: Censys match {m.get('ip')}  {hn}  ({m.get('asn') or '?'})", "type": "warn", "stage":"S10"})
            yield sse("faviconPivotCensys", cs_piv)
        except Exception as e:
            yield sse("log", {"msg": f"S10: Favicon pivot phase failed: {e}", "type": "warn", "stage":"S10"})
    elif not is_ip:
        # No usable favicon — emit explicit skipped events so the UI panel
        # shows the actual outcome instead of an indefinite "AWAITING" state.
        skip_msg = "skipped — seed favicon not retrievable"
        yield sse("faviconPivotShodan", {"matches": [], "total": 0, "skipped": True, "error": skip_msg})
        yield sse("faviconPivotCensys", {"matches": [], "total": 0, "skipped": True, "error": skip_msg})

    # If reverse-NS didn't run (IP seed or no nameservers found), emit a
    # skipped stub for the same reason — keeps the UI panel honest.
    if is_ip or not ns_list:
        yield sse("reverseNs", {"per_ns": [], "flat": [], "skipped": True,
                                 "error": ("skipped — IP seed has no nameserver pivot" if is_ip
                                           else "skipped — no nameservers identified for seed")})

    # Same for the JARM pivot when no Shodan data was available
    if not result.get("shodan_per_ip"):
        yield sse("jarmPivot", {"jarms": [], "skipped": True, "error": "skipped — no Shodan host data available"})

    yield sse("stage", {"n":10, "state": "done"})

    # ── S11: Google Threat Intelligence (GTI) ──
    # Shares the VT v3 surface; relationship fields (collections / threat actors /
    # malware families / campaigns / attack techniques) populate only on keys
    # with GTI entitlement. Each populated relationship → finding.
    yield sse("stage", {"n":11, "state": "active"})
    if VIRUSTOTAL_API_KEY:
        try:
            gti_data = await fetch_gti_intel(seed, VIRUSTOTAL_API_KEY)
            result["gti"] = gti_data
            if gti_data.get("error"):
                yield sse("log", {"msg": f"S11: GTI: {gti_data['error']}", "type": "warn", "stage":"S11"})
            elif not gti_data.get("found"):
                yield sse("log", {"msg": f"S11: GTI: {seed} not in corpus", "type": "info", "stage":"S11"})
            else:
                if gti_data.get("gti_enabled"):
                    summary = []
                    if gti_data.get("threat_actors"): summary.append(f"{len(gti_data['threat_actors'])} actor(s)")
                    if gti_data.get("malware_families"): summary.append(f"{len(gti_data['malware_families'])} malware family/-ies")
                    if gti_data.get("campaigns"): summary.append(f"{len(gti_data['campaigns'])} campaign(s)")
                    if gti_data.get("collections"): summary.append(f"{len(gti_data['collections'])} collection(s)")
                    if summary:
                        yield sse("log", {"msg": f"S11: GTI entitlement active — {', '.join(summary)}", "type": "warn", "stage":"S11"})
                    else:
                        yield sse("log", {"msg": "S11: GTI entitlement active — assessment + attribution present", "type": "warn", "stage":"S11"})
                else:
                    yield sse("log", {"msg": "S11: No GTI/Mandiant signals on this seed (key may still have entitlement; this object just has none)", "type": "info", "stage":"S11"})
                # Stream named threat actors / malware / campaigns to the log so
                # the analyst sees them inline instead of having to dig into the
                # findings panel.
                for ta in (gti_data.get("threat_actors") or [])[:4]:
                    nm = ta.get("name") or ta.get("id") or "?"
                    desc = (ta.get("description") or "")[:140]
                    yield sse("log", {"msg": f"S11: Threat actor: {nm}" + (f" — {desc}" if desc else ""), "type": "warn", "stage":"S11"})
                for mf in (gti_data.get("malware_families") or [])[:4]:
                    nm = mf.get("name") or mf.get("id") or "?"
                    yield sse("log", {"msg": f"S11: Malware family: {nm}", "type": "warn", "stage":"S11"})
                for cm in (gti_data.get("campaigns") or [])[:4]:
                    nm = cm.get("name") or cm.get("id") or "?"
                    yield sse("log", {"msg": f"S11: Campaign: {nm}", "type": "warn", "stage":"S11"})
                # Re-emit GTI's `last_dns_records` as standard dnsRecord events
                # so the DNS RECORDS panel surfaces them even when the live S2
                # DNS resolver returned nothing (Cloudflare-hosted apex, etc.).
                for rec in (gti_data.get("last_dns_records") or []):
                    rtype = (rec.get("type") or "").upper()
                    if rtype in ("A", "AAAA", "NS", "MX", "CNAME", "TXT", "SOA"):
                        yield sse("dnsRecord", {
                            "type": rtype,
                            "value": rec.get("value", ""),
                            "ttl": rec.get("ttl", ""),
                            "source": f"gti:{seed}",
                        })
                # Vendor verdict count — useful even when GTI-tier is absent
                mc = gti_data.get("malicious_vendor_count", 0)
                tc = gti_data.get("total_vendor_count", 0)
                if mc:
                    yield sse("log", {"msg": f"S11: {mc}/{tc} security vendors flag this seed as malicious", "type": "warn", "stage":"S11"})
                for f in _findings_from_gti(gti_data, context_seed=seed):
                    yield sse("finding", f)
            yield sse("gti", gti_data)
        except Exception as e:
            yield sse("log", {"msg": f"S11: GTI lookup failed: {e}", "type": "warn", "stage":"S11"})
    else:
        yield sse("log", {"msg": "S11: GTI skipped — VirusTotal API key not configured", "type": "info", "stage":"S11"})
    yield sse("stage", {"n":11, "state": "done"})

    # ── S12: Additional Infrastructure Mapping ──
    yield sse("stage",{"n":12,"state":"active"})
    yield sse("log",{"msg":"S12: Performing reverse IP lookup expansion to map hosting provider networks","type":"live","stage":"S12"})
    
    try:
        if not feat("reverse_ip"): raise _StageDisabled
        # Perform reverse IP lookup for each discovered IP
        reverse_ip_data = []
        for ip in ips[:5]:  # Check first 5 IPs
            try:
                reverse_data = await fetch_reverse_ip_lookup(ip)
                reverse_ip_data.append(reverse_data)
                if not reverse_data.get("error"):
                    domain_count = reverse_data.get("count", 0)
                    if domain_count > 0:
                        yield sse("log",{"msg":f"S12: Reverse IP lookup for {ip} found {domain_count} domains","type":"ok","stage":"S12"})
                        # Show first 3 domains for context
                        domains = reverse_data.get("domains", [])[:3]
                        for domain in domains:
                            yield sse("log",{"msg":f"S12: Neighbor domain: {domain}","type":"ok","stage":"S12"})
                    else:
                        yield sse("log",{"msg":f"S12: Reverse IP lookup for {ip} found no additional domains","type":"info","stage":"S12"})
                else:
                    yield sse("log",{"msg":f"S12: Reverse IP lookup failed for {ip}: {reverse_data.get('error')}","type":"warn","stage":"S12"})
            except Exception as e:
                yield sse("log",{"msg":f"S12: Reverse IP lookup failed for {ip}: {str(e)}","type":"warn","stage":"S12"})
        
        # Store reverse IP data for correlation
        result["reverse_ip"] = reverse_ip_data

        # Stream the aggregated entries to the frontend so the NEIGHBOR DOMAINS
        # panel can render incrementally instead of waiting for the whole pipeline
        # to finish. Only entries that actually returned domains are sent — the
        # client dedupes and re-aggregates per domain across IPs.
        live_entries = [e for e in reverse_ip_data if not e.get("error") and (e.get("domains") or [])]
        if live_entries:
            yield sse("reverseIp", {"entries": live_entries})

        # Correlate IP neighbors to map hosting provider networks
        ip_correlation = correlate_ip_neighbors(result.get("ip_results", []), reverse_ip_data)
        result["ip_correlation"] = ip_correlation
        
        # Identify shared infrastructure patterns
        shared_infra = identify_shared_infrastructure(ip_correlation)
        result["shared_infrastructure"] = shared_infra
        
        # Log findings
        if shared_infra.get("common_ips"):
            yield sse("log",{"msg":f"S12: Found {len(shared_infra['common_ips'])} IPs hosting multiple domains - potential shared infrastructure","type":"warn","stage":"S12"})
        
        if shared_infra.get("infrastructure_clusters"):
            cluster_count = len(shared_infra["infrastructure_clusters"])
            yield sse("log",{"msg":f"S12: Identified {cluster_count} infrastructure clusters","type":"warn","stage":"S12"})
            
        for pattern in shared_infra.get("suspicious_patterns", []):
            yield sse("log",{"msg":f"S12: {pattern}","type":"warn","stage":"S12"})
            
    except _StageDisabled:
        yield sse("log",{"msg":"S12: Reverse IP / infrastructure mapping disabled in settings","type":"info","stage":"S12"})
    except Exception as e:
        yield sse("log",{"msg":f"S12: Infrastructure mapping failed: {str(e)}","type":"warn","stage":"S12"})

    yield sse("stage",{"n":12,"state":"done"})

    # ── S13: Multi-Platform IOC Correlation ──
    yield sse("stage",{"n":13,"state":"active"})
    yield sse("log",{"msg":"S13: Performing Multi-Platform IOC Correlation with VirusTotal, AlienVault OTX, URLHaus","type":"live","stage":"S13"})
    
    try:
        if not feat("correlation"): raise _StageDisabled
        # Extract IOCs from discovered domains for correlation
        iocs_to_correlate = [d["name"] for d in result.get("domains", []) if d.get("name")]
        
        # Add any discovered IP addresses
        for ip_info in result.get("ip_results", []):
            if ip_info.get("query"):
                iocs_to_correlate.append(ip_info["query"])
        
        if iocs_to_correlate:
            # Perform IOC correlation across threat feeds
            correlation_results = await correlate_iocs_with_threat_feeds(iocs_to_correlate)
            result["ioc_correlation"] = correlation_results
            
            # Analyze correlation results for patterns
            correlation_analysis = analyze_correlation_results(correlation_results)
            result["correlation_analysis"] = correlation_analysis
            
            # Log findings
            summary = correlation_results.get("summary", {})
            total_iocs = summary.get("total_iocs", 0)
            correlated_count = summary.get("correlated_iocs", 0)
            high_confidence = summary.get("high_confidence_count", 0)
            medium_confidence = summary.get("medium_confidence_count", 0)
            
            yield sse("log",{"msg":f"S13: Multi-Platform IOC Correlation complete - {correlated_count}/{total_iocs} IOCs correlated","type":"ok","stage":"S13"})
            
            if high_confidence > 0:
                yield sse("log",{"msg":f"S13: !! HIGH CONFIDENCE IOC MATCHES: {high_confidence} IOCs with high confidence threat intelligence","type":"err","stage":"S13"})
                
            if medium_confidence > 0:
                yield sse("log",{"msg":f"S13: Medium confidence IOC matches: {medium_confidence} IOCs","type":"warn","stage":"S13"})
            
            # Send correlation data to frontend
            yield sse("iocCorrelation",{"correlation_results": correlation_results, "analysis": correlation_analysis})
            
        else:
            yield sse("log",{"msg":"S13: No IOCs available for correlation","type":"info","stage":"S13"})
            
    except _StageDisabled:
        yield sse("log",{"msg":"S13: Multi-Platform IOC Correlation disabled in settings","type":"info","stage":"S13"})
    except Exception as e:
        yield sse("log",{"msg":f"S13: Multi-Platform IOC Correlation failed: {str(e)}","type":"warn","stage":"S13"})

    yield sse("stage",{"n":13,"state":"done"})

    # ── S14: SSL Certificate Graph Analysis ──
    yield sse("stage",{"n":14,"state":"active"})
    yield sse("log",{"msg":"S14: Performing SSL Certificate Graph Analysis","type":"live","stage":"S14"})
    
    try:
        if not feat("ssl_graph"): raise _StageDisabled
        # Get certificates from result
        certs = result.get("certs", [])
        if not certs:
            # If no certs in result, try to get from domains stage
            certs = await fetch_crtsh(seed, ct_sources)

        if certs:
            # Perform extended certificate analysis
            cert_analysis = await fetch_extended_certificate_analysis(certs)
            result["cert_graph"] = cert_analysis
            
            # Log findings
            if cert_analysis.get("analysis_complete", False):
                graph = cert_analysis.get("graph", {})
                risk_score = cert_analysis.get("risk_score", 0)
                
                yield sse("log",{"msg":f"S14: SSL Certificate Graph Analysis complete - Risk Score: {risk_score}/100","type":"ok","stage":"S14"})
                
                # Log certificate families
                families = graph.get("certificate_families", [])
                if families:
                    large_families = [f for f in families if f["family_size"] == "large"]
                    if large_families:
                        yield sse("log",{"msg":f"S14: Found {len(large_families)} large certificate families - potential shared infrastructure","type":"warn","stage":"S14"})
                        for family in large_families[:3]:  # Show first 3
                            yield sse("log",{"msg":f"S14: Large family: {family['issuer']} with {family['domain_count']} domains","type":"warn","stage":"S14"})
                
                # Log issuer migrations
                migrations = graph.get("issuer_migrations", [])
                if migrations:
                    yield sse("log",{"msg":f"S14: Found {len(migrations)} domains with issuer migration patterns","type":"warn","stage":"S14"})
                    for migration in migrations[:3]:  # Show first 3
                        yield sse("log",{"msg":f"S14: Domain {migration['domain']} migrated between {migration['migration_count']} issuers","type":"warn","stage":"S14"})
                
                # Log suspicious chains
                suspicious = graph.get("suspicious_chains", [])
                if suspicious:
                    yield sse("log",{"msg":f"S14: Found {len(suspicious)} domains with suspicious certificate chains","type":"err","stage":"S14"})
                    for chain in suspicious[:3]:  # Show first 3
                        yield sse("log",{"msg":f"S14: Suspicious chain: {chain['domain']} issued by '{chain['issuer']}'","type":"err","stage":"S14"})
                
                # Send graph data to frontend
                yield sse("certGraph",{"graph": graph, "risk_score": risk_score})
            else:
                yield sse("log",{"msg":"S14: SSL Certificate Graph Analysis failed or incomplete","type":"warn","stage":"S14"})
        else:
            yield sse("log",{"msg":"S14: No certificates available for graph analysis","type":"info","stage":"S14"})
            
    except _StageDisabled:
        yield sse("log",{"msg":"S14: SSL Certificate Graph Analysis disabled in settings","type":"info","stage":"S14"})
    except Exception as e:
        yield sse("log",{"msg":f"S14: SSL Certificate Graph Analysis failed: {str(e)}","type":"warn","stage":"S14"})

    yield sse("stage",{"n":14,"state":"done"})

    # ── S15: Social Media & Content Platform Fingerprinting ──
    yield sse("stage",{"n":15,"state":"active"})
    yield sse("log",{"msg":"S15: Performing Social Media & Content Platform Fingerprinting","type":"live","stage":"S15"})
    
    try:
        if not feat("social_fingerprint"): raise _StageDisabled
        # Check for social media and content platform presence
        social_media_data = await check_social_media_presence(result.get("domains", []))
        result["social_media_fingerprinting"] = social_media_data
        
        # Map content similarity across platforms
        content_similarity_data = map_content_similarity(result.get("domains", []))
        result["content_similarity"] = content_similarity_data
        
        # Log findings
        if social_media_data.get("analysis_complete", False):
            social_score = social_media_data.get("social_platform_score", 0)
            total_matches = social_media_data.get("total_matches", 0)
            yield sse("log",{"msg":f"S15: Social Media Fingerprinting complete - Score: {social_score}/100, Matches: {total_matches}","type":"ok","stage":"S15"})
            
            # Log specific matches
            social_matches = social_media_data.get("social_media_matches", [])
            content_matches = social_media_data.get("content_platform_matches", [])
            
            if social_matches:
                plats = ", ".join(social_media_data.get("platforms_found", [])) or "various"
                yield sse("log",{"msg":f"S15: {len(social_matches)} real social/contact links found in homepages ({plats})","type":"warn","stage":"S15"})
                for match in social_matches[:5]:  # Show first 5 with the actual URL
                    yield sse("log",{"msg":f"S15: {match['domain']} → {match['platform']}: {match.get('url','')}","type":"warn","stage":"S15"})
            else:
                yield sse("log",{"msg":f"S15: No social/contact links found in {social_media_data.get('domains_scanned',0)} scanned homepage(s)","type":"info","stage":"S15"})
                    
            suspicious_patterns = social_media_data.get("suspicious_patterns", [])
            if suspicious_patterns:
                yield sse("log",{"msg":f"S15: Found {len(suspicious_patterns)} suspicious social media patterns","type":"err","stage":"S15"})
                for pattern in suspicious_patterns[:3]:  # Show first 3
                    yield sse("log",{"msg":f"S15: Suspicious pattern: {pattern['domain']} ({pattern['pattern']})","type":"err","stage":"S15"})
        
        if content_similarity_data.get("analysis_complete", False):
            similarity_score = content_similarity_data.get("content_similarity_score", 0)
            group_count = len(content_similarity_data.get("similarity_groups", {}))
            yield sse("log",{"msg":f"S15: Content Similarity Mapping complete - Score: {similarity_score}/100, Groups: {group_count}","type":"ok","stage":"S15"})
            
            # Log similarity groups
            similarity_groups = content_similarity_data.get("similarity_groups", {})
            if similarity_groups:
                yield sse("log",{"msg":f"S15: Found {len(similarity_groups)} content similarity groups","type":"warn","stage":"S15"})
                for pattern, domains in list(similarity_groups.items())[:3]:  # Show first 3 groups
                    yield sse("log",{"msg":f"S15: Similarity group '{pattern}': {len(domains)} domains","type":"warn","stage":"S15"})
                    
        # Send data to frontend
        yield sse("socialMediaData",{
            "social_media": social_media_data,
            "content_similarity": content_similarity_data
        })
        
    except _StageDisabled:
        yield sse("log",{"msg":"S15: Social Media & Content Platform Fingerprinting disabled in settings","type":"info","stage":"S15"})
    except Exception as e:
        yield sse("log",{"msg":f"S15: Social Media & Content Platform Fingerprinting failed: {str(e)}","type":"warn","stage":"S15"})

    yield sse("stage",{"n":15,"state":"done"})


    # ── S16: Recursive Subdomain Discovery ──
    yield sse("stage",{"n":16,"state":"active"})
    yield sse("log",{"msg":"S16: Performing Recursive Subdomain Discovery & Brute-forcing","type":"live","stage":"S16"})
    
    try:
        # Check if subdomain discovery is enabled in settings
        if not feat("subdomain_discovery"): raise _StageDisabled
        if is_ip: raise _StageDisabled  # subdomain enumeration needs a domain
        subdomain_data = await fetch_subdomain_enumeration(seed, VIRUSTOTAL_API_KEY)
        result["subdomain_discovery"] = subdomain_data
        
        if not subdomain_data.get("error"):
            subdomain_count = subdomain_data.get("subdomain_count", 0)
            if subdomain_count > 0:
                yield sse("log",{"msg":f"S16: Discovered {subdomain_count} additional subdomains through recursive enumeration","type":"ok","stage":"S16"})
                
                # Add newly discovered subdomains to the domain list
                new_subdomains = subdomain_data.get("subdomains", [])
                for subdomain in new_subdomains:
                    if not any(d["name"] == subdomain for d in result["domains"]):
                        flag = "NEIBU" if subdomain.startswith("neibu") else None
                        label = subdomain.rsplit(".", 1)[0] if "." in subdomain else subdomain
                        result["domains"].append({
                            "name": subdomain, 
                            "source": "recursive_discovery", 
                            "flag": flag,
                            "entropy": round(shannon_entropy(label), 2)
                        })
                
                # Report admin interfaces
                admin_interfaces = subdomain_data.get("admin_interfaces", [])
                if admin_interfaces:
                    yield sse("log",{"msg":f"S16: !! ADMIN/CONTROL PANELS DETECTED: {len(admin_interfaces)} interfaces found","type":"err","stage":"S16"})
                    for interface in admin_interfaces[:5]:  # Show first 5
                        yield sse("log",{"msg":f"S16: Admin interface: {interface['subdomain']} ({interface['type']})","type":"err","stage":"S16"})
                
                # Report internal infrastructure
                internal_infra = subdomain_data.get("internal_infrastructure", {})
                neibu_count = len(internal_infra.get("neibu", []))
                kyc_count = len(internal_infra.get("kyc", []))
                internal_count = len(internal_infra.get("internal", []))
                
                if neibu_count > 0:
                    yield sse("log",{"msg":f"S16: !! NEIBU 内部 ADMIN PANELS: {neibu_count} Chinese-dev admin interfaces detected","type":"err","stage":"S16"})
                if kyc_count > 0:
                    yield sse("log",{"msg":f"S16: KYC Infrastructure: {kyc_count} Know Your Customer systems detected","type":"warn","stage":"S16"})
                if internal_count > 0:
                    yield sse("log",{"msg":f"S16: Internal Infrastructure: {internal_count} internal systems detected","type":"warn","stage":"S16"})
                
                # Send subdomain discovery data to frontend
                yield sse("subdomainDiscovery",{"data": subdomain_data})
                yield sse("chip",{"id":"subdomain","state":"live"})
            else:
                yield sse("log",{"msg":"S16: No additional subdomains discovered through recursive enumeration","type":"info","stage":"S16"})
                yield sse("chip",{"id":"subdomain","state":"pend"})
        else:
            yield sse("log",{"msg":f"S16: Subdomain discovery failed: {subdomain_data.get('error')}","type":"warn","stage":"S16"})
            yield sse("chip",{"id":"subdomain","state":"fail"})
            
    except _StageDisabled:
        yield sse("log",{"msg":"S16: Recursive Subdomain Discovery disabled in settings","type":"info","stage":"S16"})
        yield sse("chip",{"id":"subdomain","state":"pend"})
    except Exception as e:
        yield sse("log",{"msg":f"S16: Recursive Subdomain Discovery failed: {str(e)}","type":"warn","stage":"S16"})
        yield sse("chip",{"id":"subdomain","state":"fail"})

    yield sse("stage",{"n":16,"state":"done"})

    # ── S17: Neighbor CT enrichment ──
    # Cert-transparency on each reverse-IP and reverse-NS neighbor. Surfaces when
    # neighbors first showed up in CT logs — issuance bursts across neighbors are
    # a campaign signal even when the individual names look unrelated.
    yield sse("stage",{"n":17,"state":"active"})
    yield sse("log",{"msg":"S17: CT enrichment on neighbor / IP-hosted domains","type":"live","stage":"S17"})
    try:
        neighbor_pool: list[str] = []
        seed_norm = (seed or "").lower().strip(".")
        for entry in result.get("reverse_ip", []) or []:
            if entry.get("error"): continue
            for d in (entry.get("domains") or []):
                if d and d.lower() != seed_norm:
                    neighbor_pool.append(d)
        for row in ((result.get("reverse_ns") or {}).get("flat") or []):
            host = row.get("hostname")
            if host and host.lower() != seed_norm:
                neighbor_pool.append(host)
        if neighbor_pool:
            ct_summaries = await enrich_neighbors_with_ct(neighbor_pool, limit=25)
            result["neighbor_ct"] = ct_summaries
            if ct_summaries:
                yield sse("neighborCt", {"summaries": ct_summaries})
                yield sse("log",{"msg":f"S17: CT enrichment found certs for {len(ct_summaries)}/{min(25,len(neighbor_pool))} neighbor domains","type":"ok","stage":"S17"})
            else:
                yield sse("log",{"msg":"S17: CT enrichment — no neighbor domains had certspotter coverage","type":"info","stage":"S17"})
        else:
            yield sse("log",{"msg":"S17: CT enrichment skipped — no neighbor domains to enrich","type":"info","stage":"S17"})
    except Exception as e:
        yield sse("log",{"msg":f"S17: CT enrichment failed: {e}","type":"warn","stage":"S17"})
    yield sse("stage",{"n":17,"state":"done"})

    # Close the self-tracking scan row so future diff queries can find it.
    try:
        if scan_id:
            pdns_store.finish_scan(scan_id)
            # Run diff against the most-recent prior completed scan, if any.
            current_state = pdns_store.query_scan_state(scan_id) or {}
            diff = diff_engine.diff_against_history(seed, current_state)
            if not diff.get("error"):
                s = diff.get("summary") or {}
                yield sse("log",
                          {"msg": f"DIFF: {s.get('added_count',0)} new IP(s), "
                                  f"{s.get('removed_count',0)} removed, "
                                  f"{s.get('stable_count',0)} stable since prior scan",
                           "type": "warn" if (s.get("added_count",0) or s.get("removed_count",0)) else "info",
                           "stage": "DIFF"})
                yield sse("diff", diff)
    except Exception as e:
        yield sse("log", {"msg": f"DIFF: finish/diff failed: {e}", "type": "warn", "stage": "DIFF"})

    yield sse("log",{"msg":f"Pipeline complete — {len(result['domains'])} domains mapped","type":"ok","stage":"DONE"})
    # Final event the frontend waits on: hands over the full result, stops the run
    # indicator/spinners, enables exports, and lets it close the stream cleanly
    # (without this, the stream just ends and EventSource reports a spurious error).
    yield sse("complete",{"result":result})

# ════════════════════════════════════════════════════════════
# API ROUTES
# ════════════════════════════════════════════════════════════

def _parse_settings_csv(value: str | None, default: set[str]) -> set[str]:
    """Parse a comma-separated settings list from the query string.
    None (param omitted) -> default (all enabled, for backward compatibility).
    "" (param present but empty) -> empty set (everything disabled)."""
    if value is None:
        return set(default)
    return {v.strip() for v in value.split(",") if v.strip()}

@app.get("/api/pipeline/standard")
async def pipeline_standard(
    seed: str = Query(...),
    ct_sources: str | None = Query(None),
    features: str | None = Query(None),
):
    validated, kind = validate_seed(seed)
    if not validated or kind not in ("domain", "ip"):
        return JSONResponse({"error":"Enter a valid domain or public IP address"},status_code=400)
    ct = _parse_settings_csv(ct_sources, set(DEFAULT_CT_SOURCES))
    feats = _parse_settings_csv(features, {
        "reverse_ip","asn_intel","ssl_graph","timeline","correlation",
        "social_fingerprint","subdomain_discovery","revalidation"})
    return StreamingResponse(run_standard_pipeline(validated, ct, feats),
        media_type="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

@app.get("/api/dns")
async def api_dns(domain: str = Query(...), types: str = Query("A,AAAA,MX,NS,TXT,CNAME,SOA,CAA")):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    results = {}
    for rtype in types.split(","):
        try:
            res = await fetch_dns(validated, rtype.strip().upper())
            if res.get("Answer"): results[rtype.strip().upper()] = res["Answer"]
        except Exception: pass
    return JSONResponse(results)

@app.get("/api/ip/{ip}")
async def api_ip(ip: str):
    validated = validate_ip(ip)
    if not validated: return JSONResponse({"error":"Invalid or private IP"},status_code=400)
    try: return JSONResponse(await fetch_ipinfo(validated))
    except Exception as e: return JSONResponse({"error":str(e)},status_code=502)

@app.get("/api/rdap/{domain}")
async def api_rdap(domain: str):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    # RDAP first; fall back to passive public WHOIS for TLDs RDAP doesn't cover.
    try: return JSONResponse(await fetch_domain_registration(validated))
    except Exception as e: return JSONResponse({"error":str(e)},status_code=502)

@app.get("/api/registrable")
async def api_registrable(domain: str = Query(..., description="Domain or subdomain to extract eTLD+1 from")):
    """Resolve any FQDN/subdomain to its registered domain (eTLD+1).

    Used by Investigator mode so a single random subdomain like
    `r8cgf6ux.luxerabet100.com` is correctly pivoted to `luxerabet100.com`
    before hitting crt.sh. Without this, the wildcard CT query only returns
    certs for the exact subdomain, missing the entire sister-domain cluster.
    """
    validated = validate_domain(domain)
    if not validated:
        return JSONResponse({"error": "Invalid domain", "input": domain}, status_code=400)
    sld = registrable_domain(validated)
    if not sld:
        return JSONResponse({"error": "Could not extract registered domain", "input": domain}, status_code=422)
    return {
        "input":    validated,
        "registrable": sld,
        "changed":  sld != validated,
        "dropped_labels": validated[:-len(sld)].rstrip('.') if sld and sld != validated else "",
    }

@app.get("/api/certs/{domain:path}")
async def api_certs(domain: str):
    raw = domain.lstrip("%.").lstrip("*.")
    validated = validate_domain(raw)
    if not validated: return JSONResponse({"error":"Invalid domain"},status_code=400)
    try:
        certs = await fetch_crtsh(validated)
    except Exception as e:
        return JSONResponse({"error":f"Certificate transparency sources unavailable: {e}"},status_code=502)
    return JSONResponse({"count":len(certs),"certs":certs[:200]})

@app.get("/api/urlscan/{seed}")
async def api_urlscan(seed: str):
    validated, kind = validate_seed(seed)
    if not validated: return JSONResponse({"error":"Invalid domain or IP"},status_code=400)
    return JSONResponse(await fetch_urlscan(validated))

@app.get("/api/shodan/{ip}")
async def api_shodan(ip: str):
    validated = validate_ip(ip)
    if not validated: return JSONResponse({"error":"Invalid or private IP"},status_code=400)
    return JSONResponse(await fetch_shodan_data(validated, SHODAN_API_KEY))


@app.get("/api/virustotal/{domain}")
async def api_virustotal(domain: str):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    return JSONResponse(await fetch_virustotal_passive_dns(validated, VIRUSTOTAL_API_KEY))


# VT reputation cache — the free tier caps at 4 req/min, and analysts often
# inspect the same cluster repeatedly. A short in-memory TTL cache keeps the
# bulk-neighbor lookups under the rate limit and makes re-renders instant.
_VT_REP_CACHE: dict = {}
_VT_REP_TTL = 6 * 3600  # 6 hours

@app.get("/api/vt-reputation/{seed}")
async def api_vt_reputation(seed: str):
    """Reputation summary (malicious/suspicious/harmless counts + verdict) from
    VirusTotal — accepts a domain or a public IP."""
    validated, kind = validate_seed(seed)
    if not validated or kind not in ("domain", "ip"):
        return JSONResponse({"error": "Invalid domain or IP"}, status_code=400)
    now = time.time()
    cached = _VT_REP_CACHE.get(validated)
    if cached and (now - cached[0]) < _VT_REP_TTL:
        return JSONResponse({**cached[1], "cached": True})
    data = await fetch_virustotal_reputation(validated, VIRUSTOTAL_API_KEY)
    # Only cache successful lookups so transient errors don't poison the cache.
    if "error" not in data:
        _VT_REP_CACHE[validated] = (now, data)
    # Promote vendor-count / reputation findings to top-level so callers don't
    # have to apply the threshold logic themselves.
    enriched = {**data, "findings": _findings_from_vt(data, context_seed=validated)}
    return JSONResponse(enriched)

@app.get("/api/bulk")
async def api_bulk(iocs: str = Query(...)):
    raw_list = [i.strip() for i in iocs.split(",") if i.strip()][:50]
    results = []
    for raw in raw_list:
        validated, kind = validate_seed(raw)
        if not validated: continue
        r = {"ioc":validated,"type":kind,"resolves":False,"isp":"?","asn":"?","country":"?","created":"?","status":"?"}
        try:
            if kind=="domain":
                dns = await fetch_dns(validated,"A")
                ips_found = [a["data"] for a in (dns.get("Answer") or []) if validate_ip(a["data"])]
                r["resolves"] = bool(ips_found)
                if ips_found:
                    await asyncio.sleep(0.3)
                    info = await fetch_ipinfo(ips_found[0])
                    r.update({"isp":info.get("isp","?"),"asn":info.get("as","?"),"country":info.get("countryCode","?")})
                try:
                    rdap = await fetch_rdap(validated)
                    s = parse_rdap_summary(rdap)
                    r["created"] = s["created"][:10] if s["created"]!="?" else "?"
                    r["status"] = s["status"][:30]
                except Exception: pass
            else:
                info = await fetch_ipinfo(validated)
                r.update({"resolves":True,"isp":info.get("isp","?"),"asn":info.get("as","?"),"country":info.get("countryCode","?")})
        except Exception as e: r["error"]=str(e)
        results.append(r)
        await asyncio.sleep(0.2)
    return JSONResponse({"results":results})

async def check_domain_active(domain: str) -> dict:
    """Live DNS lookup to determine whether a lookalike domain is actually
    registered and resolving (i.e. a live phishing host vs. just a permutation).
    Returns resolution state plus signals (A records, MX = mail-capable)."""
    info = {"active": False, "ips": [], "has_mx": False}
    try:
        a = await fetch_dns(domain, "A")
        ips = [ans["data"] for ans in (a.get("Answer") or []) if validate_ip(ans.get("data",""))]
        if ips:
            info["active"] = True
            info["ips"] = ips[:3]
    except Exception:
        pass
    if info["active"]:
        try:
            mx = await fetch_dns(domain, "MX")
            info["has_mx"] = bool(mx.get("Answer"))
        except Exception:
            pass
    return info

# Short-lived cache so repeated popup clicks and the brand-vs-permutation
# registrar comparison don't re-hit RDAP/IP services for the same domain.
_domain_detail_cache: dict[str, tuple[float, dict]] = {}
_DETAIL_TTL = 300  # seconds

async def gather_domain_detail(domain: str, use_cache: bool = True) -> dict:
    """Full WHOIS/RDAP + hosting enrichment for a single domain. Used by the
    detail popup and the permutation registrar comparison. RDAP returns registrar
    data even for registered-but-not-resolving domains, so the popup is useful for
    inactive permutations too."""
    now = time.time()
    if use_cache:
        cached = _domain_detail_cache.get(domain)
        if cached and now - cached[0] < _DETAIL_TTL:
            return dict(cached[1])

    detail = {
        "domain": domain, "resolves": False, "ips": [], "has_mx": False,
        "hosting_isp": "?", "asn": "?", "country": "?",
        "registrar": "?", "created": "?", "expires": "?",
        "status": "?", "nameservers": "?", "dns": {},
    }
    act = await check_domain_active(domain)
    detail["resolves"] = act["active"]
    detail["ips"] = act["ips"]
    detail["has_mx"] = act["has_mx"]

    # Full DNS record set (so the popup can show it for IP-discovered domains too).
    async def _one_rtype(rt):
        try:
            res = await fetch_dns(domain, rt)
            return rt, [a.get("data", "") for a in (res.get("Answer") or []) if a.get("data")][:8]
        except Exception:
            return rt, []
    for rt, ans in await asyncio.gather(*[_one_rtype(t) for t in ("A","AAAA","MX","NS","TXT","CNAME")]):
        if ans:
            detail["dns"][rt] = ans
    if act["ips"]:
        try:
            info = await fetch_ipinfo(act["ips"][0])
            detail["hosting_isp"] = info.get("isp", "?")
            detail["asn"] = info.get("as", "?")
            detail["country"] = info.get("countryCode", "?")
        except Exception:
            pass
    try:
        # RDAP first, then passive public WHOIS (who-dat) for TLDs RDAP doesn't cover.
        s = await fetch_domain_registration(domain)
        detail["registrar"] = s.get("registrar", "?") or "?"
        detail["created"] = (s.get("created", "?") or "?")[:10]
        detail["expires"] = (s.get("expires", "?") or "?")[:10]
        detail["status"] = s.get("status", "?") or "?"
        detail["nameservers"] = s.get("nameservers", "?") or "?"
        detail["registration_source"] = s.get("source", "rdap")
    except Exception:
        pass

    _domain_detail_cache[domain] = (now, dict(detail))
    return detail

async def enrich_dnstwist_with_activity(typosquats: list[dict], original: str,
                                        brand_registrar: str | None = None) -> list[dict]:
    """Run a bounded-concurrency live lookup over DNSTwist permutations and flag
    which are active. Active permutations are promoted to high risk — a resolving
    typosquat is a registered, weaponizable lookalike, not just a theoretical one.
    Active permutations are additionally enriched with registrar/hosting info and
    compared against the brand's registrar (a different registrar than the brand
    points to third-party/adversarial registration)."""
    sem = asyncio.Semaphore(10)  # bound concurrent DoH/RDAP/IP lookups
    brand_reg = (brand_registrar or "").strip().lower()
    async def _one(t: dict) -> dict:
        strength = t.get("strength", 0)
        result = {
            "domain": t["domain"],
            "fuzzer": t.get("fuzzer", "unknown"),
            "strength": strength,
            "active": False, "ips": [], "has_mx": False,
            "registrar": "?", "created": "?",
            "hosting_isp": "?", "asn": "?", "country": "?",
            "same_registrar": None,  # None = unknown/not compared
            "risk": strength, "high_risk": False, "reasons": [],
        }
        async with sem:
            act = await check_domain_active(t["domain"])
            result.update(active=act["active"], ips=act["ips"], has_mx=act["has_mx"])
            if act["active"]:
                # The resolving permutations are the real threat — enrich them fully.
                risk, reasons = max(strength, 70) + 15, ["resolves to live IP"]
                result["high_risk"] = True
                if act["has_mx"]:
                    risk += 10
                    reasons.append("MX configured (mail-capable)")
                detail = await gather_domain_detail(t["domain"])
                result.update(registrar=detail["registrar"], created=detail["created"],
                              hosting_isp=detail["hosting_isp"], asn=detail["asn"],
                              country=detail["country"])
                # Registrar/WHOIS comparison against the brand.
                reg = (detail["registrar"] or "").strip().lower()
                if brand_reg and brand_reg != "?" and reg and reg != "?":
                    same = reg == brand_reg
                    result["same_registrar"] = same
                    if same:
                        reasons.append("same registrar as brand (possible defensive registration)")
                    else:
                        risk += 5
                        reasons.append(f"different registrar from brand ({detail['registrar']})")
                result["risk"], result["reasons"] = min(100, risk), reasons
        return result
    enriched = await asyncio.gather(*[_one(t) for t in typosquats])
    # Active/high-risk first, then by risk score.
    enriched.sort(key=lambda x: (x["active"], x["risk"]), reverse=True)
    return enriched

async def _phishing_collect(validated: str, progress=None):
    """Core brand-abuse analysis. `progress` is an optional async callback used by the
    streaming endpoint to report which stage is running. Returns the result payload."""
    async def step(n, label):
        if progress: await progress("phase", {"n": n, "total": 4, "label": label})
    async def note(msg, type="info"):
        if progress: await progress("log", {"msg": msg, "type": type})

    base = validated.split(".")[0]

    # ── Stage 1: Certificate transparency (best-effort, multi-source) ──
    await step(1, "Querying certificate transparency (certspotter · certkit · crt.sh)")
    certs, ct_warning = [], None
    try:
        certs = await fetch_crtsh(f"%{base}%")
    except Exception as e:
        ct_warning = ("Certificate transparency unavailable (crt.sh is often slow on broad "
                      f"brand queries — retry for CT lookalikes): {e}")
        await note(ct_warning, "warn")
    seen, lookalikes = set(), []
    for c in certs:
        for name in (c.get("name_value") or "").split("\n"):
            n = name.strip().lower().lstrip("*.")
            if n and n not in seen and DOMAIN_RE.match(n) and n != validated and base in n:
                seen.add(n)
                score = sum([40 if base in n.split(".")[0] else 0,
                             20 if any(f"-{base}" in n or f"{base}-" in n for _ in [1]) else 0,
                             sum(12 for kw in ("login","secure","verify","update","support","wallet","crypto","exchange") if kw in n),
                             10 if re.search(r'\.(cc|top|xyz|tk|pw|click|gq|cf)$', n) else 0])
                lookalikes.append({"name":n,"score":min(100,score),"issuer":c.get("issuer_name","?"),"not_before":c.get("not_before","")})
    lookalikes.sort(key=lambda x: x["score"], reverse=True)
    await note(f"Certificate transparency → {len(lookalikes)} lookalike(s)", "ok")

    # ── Stages 2-4: DNSTwist permutations → live checks → registrar comparison ──
    dnstwist, brand_registrar = [], "?"
    try:
        await step(2, "Generating DNSTwist permutations")
        brand_detail = await gather_domain_detail(validated)
        brand_registrar = brand_detail.get("registrar", "?")
        typosquats = await fetch_typosquatting(validated)
        checking = typosquats[:80]
        await note(f"{len(typosquats)} permutations generated", "ok")
        await step(3, f"Checking which of {len(checking)} permutations are live (DNS/MX)")
        dnstwist = await enrich_dnstwist_with_activity(checking, validated, brand_registrar)
        await step(4, "Comparing registrars · finalizing")
    except Exception:
        dnstwist = []
    active_count = sum(1 for d in dnstwist if d["active"])
    await note(f"{active_count} active (resolving) lookalike(s) flagged high risk",
               "err" if active_count else "ok")

    return {
        "brand": validated,
        "brand_registrar": brand_registrar,
        "count": len(lookalikes),
        "lookalikes": lookalikes[:100],
        "dnstwist": dnstwist,
        "dnstwist_count": len(dnstwist),
        "active_count": active_count,
        "ct_warning": ct_warning,
    }

@app.get("/api/phishing")
async def api_phishing(brand: str = Query(...)):
    validated = validate_domain(brand)
    if not validated: return JSONResponse({"error":"Invalid domain"},status_code=400)
    return JSONResponse(await _phishing_collect(validated))

@app.get("/api/phishing/stream")
async def api_phishing_stream(brand: str = Query(...)):
    """Streaming brand-abuse scan (SSE) so the UI can show real-time stage progress."""
    validated = validate_domain(brand)
    if not validated: return JSONResponse({"error":"Invalid domain"},status_code=400)
    async def gen():
        queue: asyncio.Queue = asyncio.Queue()
        async def progress(event, data): await queue.put((event, data))
        async def run():
            try:
                result = await _phishing_collect(validated, progress)
                await queue.put(("result", result))
            except Exception as e:
                # Custom name (not "error") so it doesn't collide with EventSource's
                # built-in transport error event on the client.
                await queue.put(("scanerror", {"message": str(e)}))
            finally:
                await queue.put((None, None))
        task = asyncio.create_task(run())
        try:
            while True:
                event, data = await queue.get()
                if event is None:
                    break
                yield sse(event, data)
        finally:
            task.cancel()
    return StreamingResponse(gen(), media_type="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

async def fetch_domain_screenshot(domain: str) -> dict:
    """Find a screenshot of a (potentially malicious) domain WITHOUT the analyst's
    browser ever connecting to it directly. Prefers a real urlscan.io scan capture;
    falls back to a WordPress mShots live render (rendered on WordPress's sandbox).
    Both are served by third parties, so viewing the screenshot is safe."""
    shot = {"urlscan": None, "mshots": None, "source": None}
    # mShots renders on demand in the user's <img> load — always available, no key.
    shot["mshots"] = f"https://s.wordpress.com/mshots/v1/{quote('https://'+domain, safe='')}?w=720&h=480"
    try:
        us = await fetch_urlscan(domain)
        shots = us.get("screenshots") or []
        if shots:
            shot["urlscan"] = shots[0]
            shot["source"] = "urlscan.io scan"
    except Exception:
        pass
    if not shot["source"]:
        shot["source"] = "live render (WordPress mShots sandbox)"
    return shot

@app.get("/api/domain-detail")
async def api_domain_detail(domain: str = Query(...), brand: str = Query(None)):
    """On-demand WHOIS/RDAP + hosting detail for a single domain, used by the
    permutation detail popup. Optionally compares registrar / nameservers / ASN
    against a brand domain. Includes a safe (third-party-rendered) screenshot."""
    validated = validate_domain(domain)
    if not validated: return JSONResponse({"error":"Invalid domain"},status_code=400)
    detail = await gather_domain_detail(validated)
    detail["screenshot"] = await fetch_domain_screenshot(validated)
    if brand:
        bv = validate_domain(brand)
        if bv and bv != validated:
            bd = await gather_domain_detail(bv)
            detail["brand"] = bv
            detail["brand_registrar"] = bd["registrar"]
            def _same(a, b):
                a = (a or "?"); b = (b or "?")
                return a != "?" and b != "?" and a.strip().lower() == b.strip().lower()
            detail["same_registrar"] = _same(detail["registrar"], bd["registrar"])
            detail["same_nameservers"] = _same(detail["nameservers"], bd["nameservers"])
            detail["same_asn"] = _same(detail["asn"], bd["asn"])
    return JSONResponse(detail)

# ════════════════════════════════════════════════════════════
# SETTINGS API ENDPOINTS
# ════════════════════════════════════════════════════════════

@app.get("/api/settings")
async def get_settings():
    """Get current settings configuration"""
    return JSONResponse({
        "shodan_api_key_configured": bool(SHODAN_API_KEY),
        "virustotal_api_key_configured": bool(VIRUSTOTAL_API_KEY),
        "alienvault_api_key_configured": bool(ALIENVAULT_API_KEY),
        "abusech_api_key_configured": bool(ABUSECH_API_KEY),
        "censys_api_key_configured": bool(CENSYS_API_ID and CENSYS_API_SECRET),
        "certspotter_api_key_configured": bool(CERTSPOTTER_API_KEY),
        "certificate_transparency_sources": {
            "certspotter": True,   # primary — free, no key required
            "certkit": True,       # free, no key required (100 certs/query free tier)
            "crtsh": True,         # fallback — free, no key required
            "censys": bool(CENSYS_API_ID and CENSYS_API_SECRET),
            "scantower": bool(CT_PROVIDERS["scantower"]["key"] and CT_PROVIDERS["scantower"]["url"]),
            "cloudflare": bool(CT_PROVIDERS["cloudflare"]["key"] and CT_PROVIDERS["cloudflare"]["url"]),
        },
        "ct_providers": {
            name: {"label": cfg["label"], "key_configured": bool(cfg["key"]), "url_configured": bool(cfg["url"])}
            for name, cfg in CT_PROVIDERS.items()
        },
        "revalidation_enabled": REVALIDATION_ENABLED,
    })

# Note: keys arrive in the JSON request body ({"key": "..."}) sent by the Settings UI,
# so these read from Body(embed=True) rather than a query parameter.
@app.post("/api/settings/shodan")
async def update_shodan_key(key: str = Body(..., embed=True)):
    """Update Shodan API key (in memory only for this session)"""
    global SHODAN_API_KEY
    SHODAN_API_KEY = key
    return JSONResponse({"status": "success", "message": "Shodan API key updated"})

@app.post("/api/settings/virustotal")
async def update_virustotal_key(key: str = Body(..., embed=True)):
    """Update VirusTotal API key (in memory only for this session)"""
    global VIRUSTOTAL_API_KEY
    VIRUSTOTAL_API_KEY = key
    return JSONResponse({"status": "success", "message": "VirusTotal API key updated"})


@app.post("/api/settings/alienvault")
async def update_alienvault_key(key: str = Body(..., embed=True)):
    """Update AlienVault OTX API key (in memory only for this session)"""
    global ALIENVAULT_API_KEY
    ALIENVAULT_API_KEY = key
    return JSONResponse({"status": "success", "message": "AlienVault OTX API key updated"})

# Accept the 'otx' alias the Settings UI uses for AlienVault OTX.
@app.post("/api/settings/otx")
async def update_otx_key(key: str = Body(..., embed=True)):
    global ALIENVAULT_API_KEY
    ALIENVAULT_API_KEY = key
    return JSONResponse({"status": "success", "message": "AlienVault OTX API key updated"})

@app.post("/api/settings/abusech")
async def update_abusech_key(key: str = Body(..., embed=True)):
    """Update abuse.ch unified Auth-Key (in memory only for this session).
    Used for ThreatFox / URLHaus / MalwareBazaar lookups."""
    global ABUSECH_API_KEY
    ABUSECH_API_KEY = key
    return JSONResponse({"status": "success", "message": "abuse.ch API key updated"})

@app.post("/api/settings/censys")
async def update_censys_key(key: str = Body(..., embed=True)):
    """Update Censys API key (in memory only for this session)
    Key should be in format 'API_ID:API_SECRET'"""
    global CENSYS_API_ID, CENSYS_API_SECRET
    if ":" in key:
        api_id, api_secret = key.split(":", 1)
        CENSYS_API_ID = api_id
        CENSYS_API_SECRET = api_secret
        return JSONResponse({"status": "success", "message": "Censys API key updated"})
    else:
        return JSONResponse({"status": "error", "message": "Invalid format. Key should be 'API_ID:API_SECRET'"})

@app.post("/api/settings/certspotter")
async def update_certspotter_key(key: str = Body(..., embed=True)):
    """Update Cert Spotter (SSLMate) API key — raises CT query rate limits."""
    global CERTSPOTTER_API_KEY
    CERTSPOTTER_API_KEY = key
    return JSONResponse({"status": "success", "message": "Cert Spotter API key updated"})

@app.post("/api/settings/ctprovider/{name}")
async def update_ct_provider(name: str, key: str = Body("", embed=True), url: str = Body("", embed=True)):
    """Configure a pluggable CT provider (certkit / scantower / cloudflare): its API
    key and a URL template containing {q} (substituted with the brand/domain)."""
    if name not in CT_PROVIDERS:
        return JSONResponse({"status": "error", "message": f"Unknown CT provider '{name}'"}, status_code=400)
    if url and "{q}" not in url:
        return JSONResponse({"status": "error",
                             "message": "URL template must contain {q} where the domain/brand goes"}, status_code=400)
    CT_PROVIDERS[name]["key"] = key
    CT_PROVIDERS[name]["url"] = url
    enabled = bool(key and url)
    return JSONResponse({"status": "success",
                         "message": f"{CT_PROVIDERS[name]['label']} {'configured and enabled' if enabled else 'updated (needs both key and URL to activate)'}",
                         "enabled": enabled})

@app.post("/api/settings/revalidation")
async def update_revalidation_enabled(enabled: bool = Query(...)):
    """Enable/disable the automated revalidation feature (Settings tab toggle)."""
    global REVALIDATION_ENABLED
    REVALIDATION_ENABLED = enabled
    return JSONResponse({"status": "success",
                         "message": f"Automated revalidation {'enabled' if enabled else 'disabled'}",
                         "revalidation_enabled": REVALIDATION_ENABLED})

@app.get("/api/subdomain/{domain}")
async def api_subdomain(domain: str):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    return JSONResponse(await fetch_subdomain_enumeration(validated, VIRUSTOTAL_API_KEY))


@app.get("/api/pdns/{domain}")
async def api_pdns(domain: str):
    """Aggregated self-tracking passive-DNS history for `domain`.

    Returns per-IP {first_observed, last_observed, sources, scan_count} pulled
    from every prior Crucible scan recorded in pdns_store. Useful when external
    sources are sparse or the domain has been seen primarily by your own runs.
    """
    validated, kind = validate_seed(domain)
    if not validated or kind != "domain":
        return JSONResponse({"error": "Invalid domain"}, status_code=400)
    history = pdns_store.query_domain_history(validated)
    scans = pdns_store.query_scans_for_seed(validated, limit=20)
    return JSONResponse({
        "domain": validated,
        "ip_count": len(history),
        "scan_count": len(scans),
        "history": history,
        "recent_scans": scans,
    })


@app.get("/api/diff/{seed}")
async def api_diff(seed: str, prior_scan_id: str | None = None):
    """Diff the latest scan of `seed` against either the previous completed scan
    (default) or a specified prior_scan_id. Returns added/removed/stable IPs
    and per-IP source-coverage changes."""
    validated, kind = validate_seed(seed)
    if not validated or kind not in ("domain", "ip"):
        return JSONResponse({"error": "Invalid seed"}, status_code=400)
    scans = pdns_store.query_scans_for_seed(validated, limit=20)
    if len(scans) < 2:
        return JSONResponse({
            "error": f"Need at least 2 scans of {validated} to diff",
            "scan_count": len(scans),
        }, status_code=400)
    current_state = pdns_store.query_scan_state(scans[0]["scan_id"])
    if prior_scan_id:
        prior_state = pdns_store.query_scan_state(prior_scan_id)
        if not prior_state:
            return JSONResponse({"error": f"Scan {prior_scan_id} not found"},
                                status_code=404)
    else:
        prior_state = pdns_store.query_scan_state(scans[1]["scan_id"])
    return JSONResponse(diff_engine.diff_scans(prior_state, current_state))


@app.get("/api/ip/{ip}/hosted-intel")
async def api_ip_hosted_intel(ip: str, max_domains: int = 15):
    """Run ThreatFox + OTX lookups over every domain hosted by this IP.

    Combines HackerTarget reverse-IP (current) with OTX passive DNS (historical)
    to discover hosted hostnames, then queries ThreatFox with the union (capped
    at max_domains) plus the IP itself.
    """
    validated, kind = validate_seed(ip)
    if not validated or kind != "ip":
        return JSONResponse({"error": "Invalid IP"}, status_code=400)
    result = await fetch_ip_hosted_domains_intel(
        validated,
        abusech_key=ABUSECH_API_KEY,
        otx_key=ALIENVAULT_API_KEY,
        max_domains=max(1, min(max_domains, 50)),
    )
    # Promote named-family / threat-type hits to a top-level `findings` list
    # so callers don't have to walk `threatfox.matches` to spot critical hits.
    result["findings"] = _findings_from_threatfox(
        result.get("threatfox") or {}, context_seed=validated,
    )
    return JSONResponse(result)


@app.get("/api/gti/{seed}")
async def api_gti(seed: str):
    """Pull Google Threat Intelligence (GTI) data for a domain or IP.

    Uses VIRUSTOTAL_API_KEY — GTI rides on the same /api/v3 surface; whether
    the relationship fields populate depends on the key's GTI entitlement
    (reported per response as `gti_enabled`).
    """
    validated, kind = validate_seed(seed)
    if not validated or kind not in ("ip", "domain"):
        return JSONResponse({"error": "Invalid IP or domain"}, status_code=400)
    gti_data = await fetch_gti_intel(validated, VIRUSTOTAL_API_KEY)
    gti_data["findings"] = _findings_from_gti(gti_data, context_seed=validated)
    return JSONResponse(gti_data)


# ════════════════════════════════════════════════════════════
# AUTOMATED REVALIDATION API ENDPOINTS
# ════════════════════════════════════════════════════════════

# Initialize the automated revalidation system
revalidation_system = None

def get_revalidation_system():
    global revalidation_system
    if revalidation_system is None:
        revalidation_system = create_automated_revalidation_system()
    return revalidation_system

def _revalidation_disabled_response():
    """Standard response when the revalidation feature is off (Settings tab)."""
    return JSONResponse(
        {"status": "disabled",
         "message": "Automated revalidation is turned off in Settings. Enable it to run checks."},
        status_code=403)

@app.post("/api/revalidation/register/{domain}")
async def register_domain_for_revalidation(domain: str, frequency_hours: int = 24):
    """Register a domain for automated revalidation monitoring"""
    if not REVALIDATION_ENABLED: return _revalidation_disabled_response()
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)

    system = get_revalidation_system()
    system.register_domain_for_revalidation(validated, frequency_hours)
    return JSONResponse({"status": "success", "message": f"Domain {validated} registered for revalidation checks"})

@app.post("/api/revalidation/unregister/{domain}")
async def unregister_domain_from_revalidation(domain: str):
    """Remove a domain from automated revalidation monitoring"""
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    
    system = get_revalidation_system()
    system.unregister_domain_from_revalidation(validated)
    return JSONResponse({"status": "success", "message": f"Domain {validated} unregistered from revalidation checks"})

@app.post("/api/revalidation/check/{domain}")
async def run_single_revalidation_check(domain: str):
    """Run a single revalidation check for a domain"""
    if not REVALIDATION_ENABLED: return _revalidation_disabled_response()
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)

    system = get_revalidation_system()
    result = await system.perform_revalidation_check(validated)
    return JSONResponse(result)

@app.post("/api/revalidation/run-scheduled")
async def run_all_scheduled_revalidations():
    """Run all scheduled revalidation checks"""
    if not REVALIDATION_ENABLED: return _revalidation_disabled_response()
    system = get_revalidation_system()
    results = await system.run_scheduled_revalidations()
    return JSONResponse({"results": results, "count": len(results)})

@app.get("/api/revalidation/decay-report")
async def get_decay_report():
    """Get infrastructure decay report"""
    system = get_revalidation_system()
    report = system.get_decay_report()
    return JSONResponse(report)

@app.get("/api/revalidation/alerts")
async def get_recent_alerts(hours: int = 24):
    """Get recent alerts"""
    system = get_revalidation_system()
    alerts = system.get_recent_alerts(hours)
    return JSONResponse({"alerts": alerts, "count": len(alerts)})

@app.get("/api/revalidation/status/{domain}")
async def get_domain_revalidation_status(domain: str):
    """Get revalidation status for a specific domain"""
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    
    system = get_revalidation_system()
    schedule_info = system.revalidation_schedule.get(validated, {})
    domain_data = system.findings_data.get(validated, {})
    
    return JSONResponse({
        "domain": validated,
        "schedule_info": schedule_info,
        "domain_data": domain_data,
        "decay_score": system.decay_scores.get(validated, 0.0)
    })


@app.get("/health")
async def health():
    return {"status":"ok","tool":"CRUCIBLE SIGINT","version":"5.1"}

@app.get("/", response_class=HTMLResponse)
async def root():
    try: return TEMPLATE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return HTMLResponse(f"<pre>ERROR: templates/index.html not found\nExpected: {TEMPLATE}</pre>",status_code=500)

if __name__ == "__main__":
    import sys, socket
    try:
        if sys.stdout.encoding and sys.stdout.encoding.lower()!="utf-8":
            sys.stdout.reconfigure(encoding="utf-8",errors="replace")
    except Exception: pass

    preferred = int(os.environ.get("PORT",8000))
    chosen = None
    for p in [preferred,8080,8888,9000,9090]:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try: s.bind(("127.0.0.1",p)); chosen=p; break
            except OSError: print(f"  Port {p} in use, trying next...")

    if not chosen: print("  ERROR: No free port found."); sys.exit(1)
    print(f"\n  CRUCIBLE SIGINT v5.1")
    print(f"  http://localhost:{chosen}")
    print(f"  Template: {TEMPLATE}")
    print(f"  Ctrl+C to stop\n")
    uvicorn.run("crucible_app:app",host="127.0.0.1",port=chosen,reload=False,log_level="info")

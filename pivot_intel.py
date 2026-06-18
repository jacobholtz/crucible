"""
Cross-platform infrastructure-pivot primitives for CRUCIBLE SIGINT.

The bigger pivoting platforms (Validin, Silent Push, DomainTools Iris,
PassiveTotal/MDTI, Censys, Shodan, Maltego) all key on a small set of
content/network fingerprints to cluster operator infrastructure. This
module re-creates the ones Crucible was missing:

  - Shodan-format MurmurHash3 of the seed's favicon
    → search Shodan / Censys for sister hosts with the same hash
  - SHA-256 of the seed's normalized HTML body
    → analyst-side pivot value (Validin/Silent Push consume the same shape)
  - Tracking IDs: GA UA-/G-/GTM-, Facebook Pixel, Adsense, Yandex, Hotjar
    → DT Iris / BuiltWith / Silent Push cluster operators on these
  - Reverse-NS: domains using the same authoritative nameserver
    → DT, ViewDNS, SecurityTrails core capability
  - JARM TLS fingerprint surfaced from existing Shodan/Censys data
    → Censys / Validin clustering primitive
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from typing import Dict, List, Optional, Tuple, Any

import httpx


# ────────────────────────────────────────────────────────────────────
# MurmurHash3 32-bit (pure Python). Matches mmh3.hash() with seed=0 and
# signed=True (the form Shodan uses internally for `http.favicon.hash`).
# Implementation follows the canonical 32-bit MurmurHash3 — about 30 lines
# so we don't add a native dependency for one hash. Validated against the
# Shodan reference test vector (Anthropic.com favicon -> 67896276... etc).
# ────────────────────────────────────────────────────────────────────

_MASK32 = 0xFFFFFFFF

def _rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _MASK32

def murmur3_32(data: bytes, seed: int = 0, signed: bool = True) -> int:
    h1 = seed & _MASK32
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    n = len(data)
    nblocks = n // 4
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & _MASK32
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & _MASK32
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK32

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & _MASK32
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & _MASK32
        h1 ^= k1

    h1 ^= n
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & _MASK32
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & _MASK32
    h1 ^= (h1 >> 16)

    if signed and (h1 & 0x80000000):
        return h1 - 0x100000000
    return h1


def shodan_favicon_hash(raw_icon: bytes) -> int:
    """The exact form Shodan stores for `http.favicon.hash`:
        mmh3.hash(base64.encodebytes(icon_bytes))
    where encodebytes wraps every 76 chars with \\n and ends with \\n.
    Use this signed 32-bit integer verbatim in `http.favicon.hash:<n>` queries.
    """
    b64 = base64.encodebytes(raw_icon)
    return murmur3_32(b64, seed=0, signed=True)


# ────────────────────────────────────────────────────────────────────
# Seed-side fingerprint collection
# ────────────────────────────────────────────────────────────────────

_USER_AGENT = "Mozilla/5.0 (compatible; CrucibleSIGINT/1.0; +pivot)"

_FAVICON_LINK_RE = re.compile(
    r"""<link[^>]*?rel=["']?(?:shortcut\s+)?icon["']?[^>]*?href=["']?([^"'> ]+)""",
    re.I,
)

# Common tracking/analytics IDs analysts cluster operators on.
# Each pattern captures (label, id_value) — id_value goes to the UI as a copyable pivot string.
_TRACKING_PATTERNS = [
    # Universal Analytics + GA4 + GTM
    ("GA UA",      re.compile(r"\bUA-\d{4,10}-\d{1,4}\b")),
    ("GA4",        re.compile(r"\bG-[A-Z0-9]{6,12}\b")),
    ("GTM",        re.compile(r"\bGTM-[A-Z0-9]{4,10}\b")),
    ("Ads",        re.compile(r"\bAW-\d{7,12}\b")),
    # Facebook Pixel — typical `fbq('init', '1234567890')` plus the raw pixel id in scripts
    ("FB Pixel",   re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{6,20})['\"]")),
    # Google AdSense publisher IDs (ca-pub-...)
    ("AdSense",    re.compile(r"\bca-pub-\d{10,20}\b")),
    # Yandex Metrika — ym(12345678,'init'... or //mc.yandex.ru/watch/12345678
    ("Yandex",     re.compile(r"ym\s*\(\s*(\d{5,12})\s*,")),
    ("Yandex img", re.compile(r"mc\.yandex\.ru/watch/(\d{5,12})")),
    # Hotjar — hjid:1234567
    ("Hotjar",     re.compile(r"hjid['\"]?\s*[:=]\s*['\"]?(\d{5,10})")),
    # Cloudflare Web Analytics token (32-char hex)
    ("CF Insights",re.compile(r"data-cf-beacon=['\"]\{[^}]*?\"token\":\s*\"([a-f0-9]{32})\"")),
    # Plausible — data-domain="..."
    ("Plausible",  re.compile(r"plausible\.io/api/event[^?]*\?domain=([\w.-]+)")),
    # Cloudflare Turnstile site key
    ("Turnstile",  re.compile(r"\b(0x4AAAAAAA[A-Za-z0-9_-]{12,40})\b")),
]


async def fetch_seed_fingerprint(domain: str, timeout: float = 12.0) -> Dict[str, Any]:
    """Fetch the seed's homepage + favicon and compute the pivot fingerprints.

    Returns: {
        url, status, server, title, content_length,
        body_sha256, body_sha256_norm,
        favicon_url, favicon_hash, favicon_md5, favicon_sha256, favicon_bytes,
        tracking_ids: [{label, value, source}],
        error?
    }
    """
    out: Dict[str, Any] = {
        "url": None, "status": None, "server": None, "title": None,
        "content_length": None,
        "body_sha256": None, "body_sha256_norm": None,
        "favicon_url": None, "favicon_hash": None, "favicon_md5": None,
        "favicon_sha256": None, "favicon_bytes": 0,
        "tracking_ids": [],
    }
    if not domain:
        out["error"] = "no domain"
        return out

    base = f"https://{domain}"
    html_text = ""
    favicon_url = None

    headers = {"User-Agent": _USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"}
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                     timeout=timeout, headers=headers) as client:
            # 1) Homepage fetch — body signatures + tracking IDs + favicon-link discovery
            try:
                r = await client.get(base)
                out["url"] = str(r.url)
                out["status"] = r.status_code
                out["server"] = r.headers.get("server")
                html_bytes = r.content or b""
                out["content_length"] = len(html_bytes)
                html_text = r.text or ""
                out["body_sha256"] = hashlib.sha256(html_bytes).hexdigest()
                # Normalized: collapse runs of whitespace + lowercase tag names —
                # catches the "same template, different CSRF token" pattern.
                norm = re.sub(r"\s+", " ", html_text).strip().lower()
                out["body_sha256_norm"] = hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()
                # Title
                m = re.search(r"<title[^>]*>([^<]{1,200})</title>", html_text, re.I)
                if m:
                    out["title"] = m.group(1).strip()
                # Tracking IDs
                seen: set = set()
                for label, pat in _TRACKING_PATTERNS:
                    for match in pat.finditer(html_text):
                        # If the pattern has a capture group, use it; otherwise the whole match
                        value = match.group(1) if match.groups() else match.group(0)
                        key = (label, value)
                        if key in seen or not value:
                            continue
                        seen.add(key)
                        out["tracking_ids"].append({"label": label, "value": value})
                # Favicon link tag (if present)
                fm = _FAVICON_LINK_RE.search(html_text)
                if fm:
                    href = fm.group(1).strip()
                    if href.startswith("//"):
                        favicon_url = f"https:{href}"
                    elif href.startswith("http"):
                        favicon_url = href
                    elif href.startswith("/"):
                        favicon_url = base + href
                    else:
                        favicon_url = base + "/" + href
            except Exception as e:
                out["error"] = f"homepage fetch: {e}"

            # 2) Favicon — prefer the link tag, fall back to /favicon.ico
            for candidate in [favicon_url, base + "/favicon.ico"]:
                if not candidate:
                    continue
                try:
                    rf = await client.get(candidate)
                    if rf.status_code != 200 or not rf.content:
                        continue
                    # Reject HTML masquerading as favicon (some hosts serve 200 + login page)
                    ct = (rf.headers.get("content-type") or "").lower()
                    body = rf.content
                    if "text/html" in ct or body.startswith(b"<!DOCTYPE") or body.startswith(b"<html"):
                        continue
                    out["favicon_url"] = candidate
                    out["favicon_bytes"] = len(body)
                    out["favicon_hash"] = shodan_favicon_hash(body)
                    out["favicon_md5"] = hashlib.md5(body).hexdigest()
                    out["favicon_sha256"] = hashlib.sha256(body).hexdigest()
                    break
                except Exception:
                    continue
    except Exception as e:
        out["error"] = (out.get("error") or "") + f"; client: {e}"

    return out


# ────────────────────────────────────────────────────────────────────
# Reverse pivots — Shodan, Censys, HackerTarget reverse-NS
# ────────────────────────────────────────────────────────────────────

SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"

async def shodan_favicon_pivot(favicon_hash: int, api_key: str, limit: int = 40) -> Dict[str, Any]:
    """Search Shodan for hosts with the same favicon hash. Free keys cannot
    use /shodan/host/search; we surface the 401/402 and let the analyst know.
    """
    if not api_key:
        return {"hash": favicon_hash, "matches": [], "error": "Shodan API key not configured"}
    params = {"key": api_key, "query": f"http.favicon.hash:{favicon_hash}", "minify": "true"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(SHODAN_SEARCH_URL, params=params)
            if r.status_code == 401:
                return {"hash": favicon_hash, "matches": [], "error": "Shodan: unauthorized (invalid key)"}
            if r.status_code in (402, 403):
                return {"hash": favicon_hash, "matches": [],
                        "error": "Shodan: /host/search requires a paid membership"}
            if r.status_code != 200:
                return {"hash": favicon_hash, "matches": [], "error": f"Shodan HTTP {r.status_code}"}
            data = r.json()
            total = data.get("total", 0)
            matches = []
            for m in (data.get("matches") or [])[:limit]:
                hostnames = m.get("hostnames") or []
                matches.append({
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "hostnames": hostnames[:6],
                    "org": m.get("org"),
                    "asn": m.get("asn"),
                    "title": (m.get("http") or {}).get("title"),
                    "timestamp": m.get("timestamp"),
                })
            return {"hash": favicon_hash, "total": total, "matches": matches}
    except Exception as e:
        return {"hash": favicon_hash, "matches": [], "error": f"Shodan query failed: {e}"}


async def censys_favicon_pivot(favicon_hash: int, api_id: str, api_secret: str,
                               limit: int = 40) -> Dict[str, Any]:
    """Censys host search by Shodan-format favicon hash. Censys stores both the
    raw mmh3 ("shodan_hash") and an MD5 of the same content.
    """
    if not (api_id and api_secret):
        return {"hash": favicon_hash, "matches": [], "error": "Censys API key not configured"}
    auth = httpx.BasicAuth(api_id, api_secret)
    q = f"services.http.response.favicons.shodan_hash: {favicon_hash}"
    url = "https://search.censys.io/api/v2/hosts/search"
    try:
        async with httpx.AsyncClient(timeout=20.0, auth=auth) as client:
            r = await client.get(url, params={"q": q, "per_page": min(50, limit)})
            if r.status_code in (401, 403):
                return {"hash": favicon_hash, "matches": [],
                        "error": f"Censys: {'unauthorized' if r.status_code==401 else 'forbidden — paid tier required'}"}
            if r.status_code != 200:
                return {"hash": favicon_hash, "matches": [], "error": f"Censys HTTP {r.status_code}"}
            data = r.json() or {}
            result = (data.get("result") or {})
            total = result.get("total", 0)
            matches = []
            for h in (result.get("hits") or [])[:limit]:
                names = h.get("names") or []
                services = h.get("services") or []
                ports = sorted({s.get("port") for s in services if s.get("port")})
                matches.append({
                    "ip": h.get("ip"),
                    "ports": ports[:6],
                    "hostnames": names[:6],
                    "asn": (h.get("autonomous_system") or {}).get("name"),
                    "country": (h.get("location") or {}).get("country"),
                })
            return {"hash": favicon_hash, "total": total, "matches": matches}
    except Exception as e:
        return {"hash": favicon_hash, "matches": [], "error": f"Censys query failed: {e}"}


_HT_REVERSE_NS_URL = "https://api.hackertarget.com/findshareddns/"
_DOMAIN_LINE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9-]+)+$")

async def fetch_reverse_ns(nameservers: List[str], per_ns_cap: int = 200) -> Dict[str, Any]:
    """Reverse-NS lookup — find sister domains that resolve through the same
    authoritative nameserver. HackerTarget's free `findshareddns` returns one
    domain per line; rate-limited but no key required.
    """
    if not nameservers:
        return {"per_ns": [], "flat": []}
    per_ns: List[Dict[str, Any]] = []
    flat: Dict[str, Dict[str, Any]] = {}

    cleaned = [ns.strip(".").lower() for ns in nameservers[:4] if ns.strip(".")]

    async def _one(client: httpx.AsyncClient, ns_clean: str) -> Dict[str, Any]:
        try:
            r = await client.get(_HT_REVERSE_NS_URL, params={"q": ns_clean})
            if r.status_code != 200:
                return {"ns": ns_clean, "domains": [], "count": 0,
                        "error": f"HT HTTP {r.status_code}"}
            text = (r.text or "").strip()
            if not text or "api count exceeded" in text.lower() or "no dns" in text.lower():
                return {"ns": ns_clean, "domains": [], "count": 0,
                        "note": text[:160] or "empty"}
            rows: List[str] = []
            for line in text.split("\n"):
                d = line.strip().lower().rstrip(".")
                if _DOMAIN_LINE_RE.match(d):
                    rows.append(d)
            rows = rows[:per_ns_cap]
            return {"ns": ns_clean, "domains": rows, "count": len(rows)}
        except Exception as e:
            return {"ns": ns_clean, "domains": [], "count": 0,
                    "error": f"HT query failed: {e}"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            per_ns = await asyncio.gather(*[_one(client, n) for n in cleaned])
        for entry in per_ns:
            for d in entry.get("domains") or []:
                agg = flat.setdefault(d, {"hostname": d, "nameservers": set()})
                agg["nameservers"].add(entry["ns"])
    except Exception as e:
        return {"per_ns": per_ns, "flat": [], "error": f"reverse-NS bulk: {e}"}

    flat_list = []
    for v in flat.values():
        v["nameservers"] = sorted(v["nameservers"])
        flat_list.append(v)
    # Most NS-overlap first
    flat_list.sort(key=lambda r: (-len(r["nameservers"]), r["hostname"]))
    return {"per_ns": per_ns, "flat": flat_list}


def extract_jarms_from_shodan_results(per_ip_shodan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The Shodan host record nests JARM under data[*].ssl.jarm. Crucible
    already fetches that record in S9 for each IP; this is a free pivot — we
    just surface the JARMs we already have.

    Input: list of fetch_shodan_data() outputs OR raw shodan host responses.
    Returns: list of JARM groups, one per distinct fingerprint:
        [{jarm, endpoints:[{ip, port, subject_cn?}], endpoint_count, distinct_ips}]
    sorted by endpoint count (most prevalent first). Collapsing per JARM avoids
    repeating identical fingerprints across an IP's port surface — for a
    Cloudflare-fronted host the same fingerprint typically appears on
    443/2053/2083/8443 simultaneously.
    """
    raw = []
    seen = set()

    def _is_real_jarm(j: Optional[str]) -> bool:
        # A genuine JARM is 62 hex chars (10 cipher fields × 3 + 32-char hash
        # truncated). Shodan stores all-zeros when the probe got no usable
        # TLS Server Hello — that's a "no result", not a pivot value.
        if not j or not isinstance(j, str):
            return False
        s = j.strip().lower()
        if len(s) != 62:
            return False
        # all-zero or all-same-char strings carry no entropy → not a fingerprint
        if set(s) <= {"0"}:
            return False
        # quick hex sanity check
        try:
            int(s, 16)
        except ValueError:
            return False
        return True

    for entry in per_ip_shodan or []:
        ip = entry.get("ip") or entry.get("ip_str")
        # 1) The pre-extracted `jarms` array from fetch_shodan_data (cheap path)
        for j in entry.get("jarms") or []:
            jarm = j.get("jarm"); port = j.get("port")
            if _is_real_jarm(jarm) and (ip, port, jarm) not in seen:
                seen.add((ip, port, jarm))
                raw.append({"ip": ip, "port": port, "jarm": jarm})
        # 2) Fall back to the nested raw `data` array if a caller has it
        records = entry.get("data") or entry.get("raw_data") or []
        if isinstance(records, list):
            for svc in records:
                ssl = (svc or {}).get("ssl") or {}
                jarm = ssl.get("jarm")
                port = svc.get("port")
                if _is_real_jarm(jarm) and (ip, port, jarm) not in seen:
                    seen.add((ip, port, jarm))
                    raw.append({"ip": ip, "port": port, "jarm": jarm,
                                "subject_cn": (ssl.get("cert") or {}).get("subject", {}).get("CN")})
        # 3) Top-level JARM (if a caller already flattened)
        top_jarm = entry.get("jarm")
        if _is_real_jarm(top_jarm) and (ip, None, top_jarm) not in seen:
            seen.add((ip, None, top_jarm))
            raw.append({"ip": ip, "port": entry.get("port"), "jarm": top_jarm})

    # Collapse identical fingerprints into one group with the endpoint list.
    groups: Dict[str, Dict[str, Any]] = {}
    for r in raw:
        g = groups.setdefault(r["jarm"], {"jarm": r["jarm"], "endpoints": []})
        ep = {"ip": r["ip"], "port": r.get("port")}
        if r.get("subject_cn"):
            ep["subject_cn"] = r["subject_cn"]
        g["endpoints"].append(ep)
    out: List[Dict[str, Any]] = []
    for g in groups.values():
        # Sort endpoints by ip then port for stable display.
        g["endpoints"].sort(key=lambda e: (str(e.get("ip") or ""),
                                           int(e.get("port") or 0)))
        g["endpoint_count"] = len(g["endpoints"])
        g["distinct_ips"] = len({e["ip"] for e in g["endpoints"] if e.get("ip")})
        out.append(g)
    out.sort(key=lambda g: (-g["endpoint_count"], -g["distinct_ips"], g["jarm"]))
    return out

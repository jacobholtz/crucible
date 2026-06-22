# CRUCIBLE SIGINT

**Passive OSINT Infrastructure Pivoting Platform — for threat intelligence, fraud investigation, and brand protection.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![OSINT](https://img.shields.io/badge/Type-Passive%20OSINT-cyan)

> *"One confirmed-bad domain → full infrastructure cluster in under 90 seconds."*

---

## Methodology Credit

**The foundational analytical approach in CRUCIBLE is directly inspired by the work of Ryan McDonald** (Principal Security Engineer | USMC 0341).

Ryan published ["Fingerprinting Malicious Infrastructure Using Free Resources"](#) (LinkedIn, May 2026), documenting his passive pivot of the **DSJ Exchange / BG Wealth Sharing LTD** pig-butchering operation — a $150M cryptocurrency fraud that victimized thousands of people, ultimately traced by FBI Operation Level Up with $41M in stolen funds frozen.

Ryan demonstrated — using only free passive sources (crt.sh, urlscan.io, DNS, WHOIS, manual JS inspection) — how a single confirmed-bad domain maps an entire 47-domain criminal infrastructure cluster, identifies on-chain wallet drain mechanisms, and reveals the two-layer brand structure of a large-scale scam operation.

**CRUCIBLE automates that methodology.** The investigative framework is Ryan's work. This tool is the automation layer built on top of it.

---

## What It Does

CRUCIBLE takes a single seed (domain or IP) and runs a 17-stage passive pipeline. Each stage emits structured events over Server-Sent Events; the UI renders them into dedicated panels, and any high-signal finding (named malware family, threat-actor attribution, suspicious vendor verdict) is elevated to a **CRITICAL FINDINGS** strip above the execution log so it doesn't scroll past.

Stages flow sequentially in execution order:

| # | Stage | Source | What It Finds |
|----|-------|--------|---------------|
| **S1** | Certificate Transparency | crt.sh + certspotter + certkit | Sister domains, NEIBU admin portals, cert timeline |
| **S2** | DNS Records | dns.google (DoH) | A/AAAA/MX/NS/TXT/SOA, parking indicators |
| **S3** | IP Intelligence | freeipapi + ip-api | ASN, ISP, hosting type, proxy/CDN detection |
| **S4** | ASN Intelligence | ipapi + local ASN DB | Hosting provider patterns, known malicious ASNs |
| **S5** | RDAP Registration | rdap.org | Registrar, creation date, status flags |
| **S6** | urlscan.io | urlscan.io | Historical scan count, additional IPs, ASNs |
| **S7** | Shodan | shodan.io | Open ports, historical IPs, device/server banners |
| **S8** | Passive DNS Aggregator | VT + OTX + CIRCL + Mnemonic + self-tracking | Historical IP resolution **with normalized ISO timestamps**, per-source provenance, vendor verdict |
| **S9** | ThreatFox + OTX Cross-Reference | abuse.ch + OTX | Malware-family attribution, pulse memberships, sister domains |
| **S10** | Platform Pivots | favicon mmh3 / body hash / JARM / reverse-NS | Shodan + Censys reverse-pivot fingerprints; identical JARMs collapse to one entry with endpoint list |
| **S11** | Google Threat Intelligence | GTI / Mandiant | Threat actors, campaigns, collections, DNS fallback when live resolution fails |
| **S12** | Reverse IP Mapping | HackerTarget | Neighbor domains, shared-hosting patterns |
| **S13** | IOC Correlation | Multi-source | Cross-platform IOC matches |
| **S14** | SSL Certificate Graph | crt.sh extended | Issuance patterns, shared-infra clusters |
| **S15** | Social Media Fingerprinting | Domain-name analysis | Social media / content platform presence, content similarity |
| **S16** | Subdomain Discovery | CT + VT + HTML + DNS brute | Subdomains via four parallel sources, per-domain evidence |
| **S17** | Neighbor CT Enrichment | certspotter | Per-domain certificate-transparency summary on reverse-IP + reverse-NS neighbors (cert count, first/last seen) |

After every scan completes, a **DIFF** event compares the run to the most recent prior scan of the same seed and reports added / removed / stable IPs and per-IP source-coverage changes.

The pipeline provides standalone HTTP endpoints for ad-hoc lookups: `/api/ip/{ip}/hosted-intel`, `/api/gti/{seed}`, `/api/subdomain/{domain}`, `/api/pdns/{domain}`, `/api/diff/{seed}`.

---

## Critical Findings Panel

Every TI source — ThreatFox, OTX pulses, VT vendor verdict, GTI threat-actor attribution, Mandiant assessment — emits structured `finding` events with a severity tier and a permalink. The frontend renders them above the execution log in a sticky panel:

| Severity | Triggered by |
|----------|--------------|
| **critical** | Named malware family (Quasar RAT, AsyncRAT, NETSUPPORT…), Mandiant threat-actor attribution, GTI verdict `malicious` with score ≥ 70, VT 5+ malicious vendors |
| **high** | OTX pulse with malicious tags but no named family, GTI campaign association or Mandiant attribution data, VT 1+ malicious or reputation ≤ −25 |
| **medium** | VT 3+ suspicious vendors |

Each row carries a `↗ open` link straight to the relevant VT / GTI / OTX permalink for analyst follow-through.

---

## Hosting IP History Panel

Every IP that has ever resolved to the seed is shown with explicit status:

- `● ACTIVE NOW` — currently in DNS
- `LAST HOSTED YYYY-MM-DD` — historical, with the most-recent observation timestamp from any source
- `LAST DATE UNKNOWN` — historical, no source carried a timestamp

Per-IP source-provenance chips (`VT` / `OTX` / `URLS` / `LIVE` / `CIRCL` / `MNEM` / `SELF`) show which feed corroborated each observation. **Timestamps are normalised to ISO-8601** at every source boundary so cross-source comparisons work even when VT returns Unix-epoch ints and OTX returns ISO strings.

---

## Multi-Source Passive DNS

S8 aggregates seven distinct sources into the single HOSTING IP HISTORY view. Coverage compounds because the sources have different gaps:

| Source | Coverage strength | Carries timestamps |
|--------|-------------------|--------------------|
| **VirusTotal passive DNS** | Global; weak on Cloudflare-Universal-SSL hosts | Yes (Unix epoch, normalised to ISO) |
| **OTX domain passive DNS** | Decent global; fills VT gaps especially on Cloudflare | Yes (ISO) |
| **CIRCL.lu passive DNS** | EU sensor network, security-research grade | Yes (Unix epoch, normalised) |
| **Mnemonic Argus passive DNS** | Nordic / EU visibility | Yes (Unix epoch, normalised) |
| **urlscan.io** | Anything urlscan crawled | No timestamps per IP |
| **Live DNS** | Right now, this instant | No (current observation) |
| **Self-tracking** | Domains *you've* scanned before | Yes (your observation timestamps) |

---

## Self-Tracking Passive DNS

`pdns_store.py` runs a local SQLite index (`crucible_pdns.sqlite` by default; configurable via `CRUCIBLE_PDNS_DB`) that records every `(domain, ip, source, observed_at)` tuple the pipeline sees. Each scan compounds the corpus:

- **Every new scan** writes its observations under a fresh `scan_id`
- **Every subsequent scan** of the same seed adds the prior observations to its HOSTING IP HISTORY panel (as the `SELF` source)
- **After a few weeks of use**, Crucible has its own passive-DNS index of the domains *you actually investigate* — closing the long-tail gap external feeds rarely fill

Schema is two tables (`pdns_observations`, `scan_runs`), inserts are idempotent on the `UNIQUE(domain, ip, source, observed_at)` constraint, and queries are exposed at:

```
GET /api/pdns/{domain}         # aggregated per-IP history + recent scans
GET /api/diff/{seed}           # diff latest scan vs. previous (or specified prior_scan_id)
```

---

## Diff Engine

`diff_engine.py` compares two scan-state snapshots from the SQLite store and surfaces what changed:

- **Added IPs** — present in current scan, absent in prior
- **Removed IPs** — present in prior, absent in current (NXDOMAIN / takedown indicator)
- **Stable IPs** — present in both
- **Source-coverage changes per IP** — gained or lost which passive-DNS sources

Diff fires automatically at the end of every pipeline run (an SSE `diff` event + a `DIFF:` log line) when there's a prior completed scan of the same seed. Also available as a standalone endpoint at `/api/diff/{seed}`.

---

## Modes

| Mode | Use Case |
|------|----------|
| **Standard** | Full passive pipeline for a single seed |
| **Investigator** | Verbose mode, raw API responses in JSON export for LEA referrals |
| **Phishing / Brand Abuse** | Point at your brand domain, find every lookalike in cert transparency |
| **Cert Intelligence** | Direct wildcard CT queries with CA distribution and issuance timeline |
| **Bulk IOC** | Enrich up to 50 domains/IPs at once, export SIEM-ready CSV |
| **Settings** | API key configuration, CT-source toggles |

---

## Installation

**Requirements:** Python 3.10+, FastAPI, httpx. API keys optional but recommended — VT/GTI is the single biggest quality lever, and CIRCL + Mnemonic significantly expand passive-DNS coverage.

```bash
git clone https://github.com/jacobholtz/crucible-sigint.git
cd crucible-sigint
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Set API keys (any subset)
export VIRUSTOTAL_API_KEY="..."      # also unlocks GTI when entitled
export ALIENVAULT_API_KEY="..."      # OTX pulses + sister-domain pivot
export ABUSECH_API_KEY="..."         # ThreatFox malware-family attribution
export SHODAN_API_KEY="..."          # JARM + open-port discovery
export CIRCL_PDNS_USERNAME="..."     # CIRCL.lu Passive DNS
export CIRCL_PDNS_PASSWORD="..."
export MNEMONIC_API_KEY="..."        # Mnemonic Argus Passive DNS

# Optional: relocate the self-tracking SQLite store
export CRUCIBLE_PDNS_DB="/path/to/crucible_pdns.sqlite"

python crucible_app.py
# → http://localhost:8000
```

API keys can also be updated at runtime from the Settings tab (in-memory for the session). See `API_KEYS.md` for the per-provider signup flow and rate limits.

---

## APIs Used

All TI sources are passive (no exploit payloads, no active scanning).

| API | Purpose | Key | Rate Limit |
|-----|---------|-----|------------|
| [crt.sh](https://crt.sh) | Primary CT logs | none | Generous, flaky |
| [certspotter.com](https://sslmate.com/certspotter/api/) | CT fallback + subdomain enum | optional | 100/h unauth |
| [dns.google](https://developers.google.com/speed/public-dns/docs/doh) | DoH | none | Unlimited |
| [rdap.org](https://rdap.org) | Domain registration | none | Generous |
| [freeipapi.com](https://freeipapi.com) | IP/ASN enrichment | none | Generous |
| [urlscan.io](https://urlscan.io/docs/api/) | Historical domain scans | none | ~1000/day |
| [shodan.io](https://shodan.io) | Open ports, JARM, banners | required | 50/day free |
| [virustotal.com](https://virustotal.com) | Passive DNS, reputation, GTI | required | 500/day free |
| [otx.alienvault.com](https://otx.alienvault.com) | Pulses, passive DNS, domain pDNS | required | Generous |
| [threatfox.abuse.ch](https://threatfox.abuse.ch) | Malware-family IOC attribution | required (auth key) | Generous |
| [Google Threat Intelligence](https://www.virustotal.com/gui/intelligence-overview) | Mandiant threat actors, campaigns | requires GTI entitlement on VT key | per VT plan |
| [circl.lu/pdns](https://www.circl.lu/services/passive-dns/) | EU passive DNS with timestamps | required (basic auth) | Researcher tier |
| [api.mnemonic.no/pdns/v3](https://docs.mnemonic.no/display/public/API/Passive+DNS+v3+API) | Nordic / EU passive DNS | required | Free tier with key |
| [hackertarget.com](https://hackertarget.com) | Reverse IP | none | Low (rate-limited) |
| [Censys](https://search.censys.io) | Favicon / JARM reverse pivot | required | per plan |
| [dnstwist](https://github.com/elceef/dnstwist) | Typosquatting (local) | none | unlimited |

---

## Exports

- **JSON** — full structured report with all signals and raw data
- **IOC CSV** — domain/IP list, SIEM-ready with source and flag columns
- **HTML Report** — standalone dark-theme report, no external dependencies
- **Copy Findings** — plain text for Slack, email, or ticketing systems

All exports support **defang toggle** — IOCs neutralised with `[.]` and `[://]` per TLP conventions before sharing.

---

## Security Design

- **No active probing** — no exploit payloads, no port scans, no authenticated requests against targets
- **All IOC data rendered as inert text** — `textContent` throughout, no `innerHTML` with external data
- **Strict input validation** — domain/IP regex before any data reaches the pipeline
- **Server-side APIs** — no CORS restrictions, no browser sandbox fighting you
- **Localhost only** — binds to `127.0.0.1`, never exposed to your network
- **API keys never logged** — runtime updates store keys in memory only; the Settings endpoint only ever returns `_configured` booleans, never key values
- **Self-tracking store is local** — `crucible_pdns.sqlite` lives next to the source on your machine; nothing is ever uploaded

---

## Project Structure

```
crucible-sigint/
├── crucible_app.py                   # FastAPI backend — SSE pipeline, all scoring, route handlers
├── intelligence_extensions.py        # External TI fetchers (VT, OTX, ThreatFox, GTI, CIRCL, Mnemonic, subdomain enum)
├── pivot_intel.py                    # Platform-pivot computation (favicon mmh3, body hash, JARM grouping)
├── infrastructure_timeline.py        # Per-IP infrastructure history tracking
├── asn_intelligence.py               # ASN-level enrichment, hosting-provider patterns
├── ioc_correlation_engine.py         # Cross-source IOC correlation
├── pdns_store.py                     # SQLite self-tracking passive-DNS index
├── diff_engine.py                    # Scan-to-scan diff (added/removed/stable IPs, source changes)
├── automated_revalidation.py         # Server-side revalidation (UI removed; API retained)
├── templates/
│   └── index.html                    # Full frontend — modes, panels, exports
├── requirements.txt
├── LICENSE                           # MIT
└── README.md
```

---

## What's New (June 2026)

This release is a substantial refactor of the original v5.1 pipeline:

- **Sequential stage numbering** — pipeline now flows S1 → S17 in execution order; no gaps, no duplicates
- **S8 unified passive-DNS aggregator** — VT + OTX + CIRCL + Mnemonic + self-tracking surface in one panel with per-source provenance and ISO timestamps
- **CIRCL.lu + Mnemonic integration** — two new external passive-DNS sources, both carrying timestamps; strong EU / Nordic visibility
- **Self-tracking passive DNS (SQLite)** — Crucible records every observation it makes; future scans compound into a private passive-DNS index
- **Diff engine** — automatic scan-to-scan comparison at pipeline completion + standalone `/api/diff/{seed}` endpoint
- **S11 Google Threat Intelligence** — Mandiant threat actors, campaigns, collections; per-relationship querying with graceful fallback; DNS fallback when live resolution fails
- **CRITICAL FINDINGS panel** — structured-event channel with clickable permalinks; severity-tiered rendering above the execution log
- **HOSTING IP HISTORY panel** — replaces IP Intelligence; per-IP ACTIVE NOW / LAST HOSTED status with cross-source provenance
- **JARM fingerprint grouping** — identical fingerprints across an IP's port surface collapse to one row with endpoint list
- **Date normalisation** — `_normalize_ts()` at every TI source boundary handles Unix-epoch ints, ISO strings, ThreatFox `YYYY-MM-DD HH:MM:SS UTC` format
- **Subdomain enumeration** — four parallel sources (CT + VT passive DNS + HTML scrape + DNS brute force) with per-subdomain evidence and label-anchored filtering
- **Removed** — legacy local threat-actor pattern matcher (S17 in old numbering) was superseded by GTI; revalidation watchlist UI was removed (server-side endpoints retained); S7 JS bundle / wallet-drain scan and JS Compromise Detector + YARA Retrohunt Generator modules removed

---

## Acknowledgements

**Ryan McDonald** — for publishing his methodology openly. The investigative approach that became CRUCIBLE's foundation was entirely his work, freely shared with the security community.

**NEATLABS™** — built as part of the NEATLABS open intelligence tooling initiative. CRUCIBLE joins a portfolio of free practitioner-grade tools at [neatlabs.ai](https://neatlabs.ai).

**Claude (Anthropic)** — the June 2026 refactor (S8 unified passive-DNS aggregator, S9/S10/S11 expansion, CRITICAL FINDINGS surface, HOSTING IP HISTORY redesign, cross-source date normalisation, JARM grouping, GTI integration fixes, CIRCL + Mnemonic integration, SQLite self-tracking PDNS, diff engine, sequential stage renumbering) was implemented pair-style with Claude Code (Opus 4.7). Architectural direction, validation against live infrastructure, and final review of each change remained with the project author.

---

## Author

**Randy B** | Security 360, LLC DBA NEATLABS™
28+ years cybersecurity · USAF Veteran · IRS/DoD practitioner
[neatlabs.ai](https://neatlabs.ai)

---

## Contributing

PRs welcome. Open questions the project would benefit from:

- **STIX 2.1 export** — for LEA and ISAC sharing
- **Diff visualisation UI** — render `/api/diff/{seed}` output as an inline panel (currently surfaces as an SSE log line + raw event)
- **Farsight DNSDB integration** — premium passive-DNS source; gold standard if budget appears
- **PDNS store retention policy** — currently unbounded; add configurable rolloff / archive for long-running deployments

---

*CRUCIBLE SIGINT is for authorised security research, threat intelligence, fraud investigation, and brand protection. Use responsibly.*

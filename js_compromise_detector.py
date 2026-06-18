"""
crucible.js_compromise_detector
===============================

Deterministic + (optional) LLM-escalated analysis of a domain's homepage and
first-party JavaScript for indicators of a compromised website used for
malicious traffic redirection (SocGholish / FakeUpdates, Parrot TDS / NDSW,
Balada Injector, ClearFake / EtherHiding, KongTuke / ClickFix, Keitaro /
BlackTDS, generic JS-based TDS handoffs).

Output is designed to feed crucible.yara_retrohunt_generator without further
processing. Each triggered_patterns entry carries the normalized snippet, line
range, source URL, plus the pattern's MITRE / tags / yara_hint enrichment.

Extending the pattern set
-------------------------
All deterministic indicators live in the PATTERNS list at the top of this
module. Each entry is a plain dict:

    {
        "name":        "snake_case_id",         # unique slug, used downstream
        "title":       "Human-readable label",
        "category":    "obfuscation" | "redirect" | "fingerprint" |
                       "antianalysis" | "infra" | "social_eng" |
                       "cryptojack" | "persistence",
        "description": "What this detects",
        "severity":    "low" | "medium" | "high" | "critical",
        "weight":      0.5 .. 3.0,              # float; contribution to score
        # exactly one of the next two:
        "regex":       r"...",                   # any single match fires
        "all_of":      [r"...", r"..."],         # all must appear in buffer
        # optional:
        "scope":       "html" | "js" | "any",   # default "any"
        "flags":       re.IGNORECASE,            # default re.MULTILINE
        "mitre":       "T1059.007 — JavaScript",
        "tags":        {"socgholish", "loader"},
        "yara_hint":   "document.write('<script", # anchor literal for YARA
    }

To add a new indicator: append to PATTERNS, restart. No analysis logic needs
to change — compile_patterns() normalizes both `regex` and `all_of` shapes.

Behavioral checks that aren't regex-shaped (entropy delta across blocks,
single-line inject at file boundary) live in STRUCTURAL_CHECKS as callables.

The LLM escalation layer is plug-in: pass any LLMClient (a Protocol) into
analyze_domain. Default is None, which disables escalation entirely. Escalation
fires only when composite_score falls inside LLM_BAND.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import Any, Callable, Literal, Optional, Protocol, Sequence, TypedDict
from urllib.parse import urljoin, urlparse

import httpx


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_SCRIPTS = 12
DEFAULT_TIMEOUT_S = 10.0
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15"
)
MAX_RESOURCE_BYTES = 2 * 1024 * 1024
SNIPPET_RADIUS = 120
SNIPPET_MAX_CHARS = 400
PER_CATEGORY_CAP = 2
DAMPENED_WEIGHT_FACTOR = 0.3

# composite_score ∈ [0, ~15+); LLM_BAND is the ambiguous middle. Below the
# floor → likely_clean; at/above the ceiling → likely_compromised. Calibrate
# against your labeled corpus before trusting these defaults.
LLM_BAND: tuple[float, float] = (2.0, 5.0)


Severity = Literal["low", "medium", "high", "critical"]
Recommendation = Literal["likely_clean", "suspicious", "likely_compromised"]


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS: list[dict[str, Any]] = [
    # === OBFUSCATION =====================================================
    {
        "name": "atob_eval_chain",
        "title": "atob + eval/Function — decoded payload execution",
        "category": "obfuscation",
        "description": "atob() output piped into eval or Function — decode-and-execute",
        "severity": "high", "weight": 2.5,
        "all_of": [r"\batob\s*\(", r"\b(?:eval|Function)\s*\("],
        "scope": "js",
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"parrot-tds", "obfuscation", "payload-delivery"},
        "yara_hint": "atob(",
    },
    {
        "name": "eval_fromCharCode_chain",
        "title": "eval + String.fromCharCode — character-code obfuscation",
        "category": "obfuscation",
        "description": "eval wrapping String.fromCharCode(...) — classic obfuscation",
        "severity": "high", "weight": 2.0,
        "regex": r"\beval\s*\(\s*String\.fromCharCode\s*\(",
        "scope": "js",
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"obfuscation", "eval-chain"},
        "yara_hint": "eval(String.fromCharCode(",
    },
    {
        "name": "function_constructor_string",
        "title": "new Function('...') — dynamic code from string",
        "category": "obfuscation",
        "description": "Function constructor invoked with a string body — eval-equivalent",
        "severity": "medium", "weight": 1.5,
        "regex": r"\bnew\s+Function\s*\(\s*['\"`]",
        "scope": "js",
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"obfuscation", "dynamic-execution"},
        "yara_hint": "new Function(",
    },
    {
        "name": "atob_long_payload",
        "title": "atob() of long base64 literal — encoded payload",
        "category": "obfuscation",
        "description": "atob called with a >=40 char base64 string literal",
        "severity": "medium", "weight": 1.5,
        "regex": r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]",
        "scope": "js",
        "mitre": "T1027 — Obfuscated Files or Information",
        "tags": {"obfuscation", "encoded-payload"},
        "yara_hint": "atob(",
    },
    {
        "name": "long_hex_escape_blob",
        "title": "Long \\xNN escape run",
        "category": "obfuscation",
        "description": "20+ consecutive \\xNN escape sequences — encoded blob",
        "severity": "medium", "weight": 1.5,
        "regex": r"(?:\\x[0-9a-fA-F]{2}){20,}",
        "scope": "js",
        "mitre": "T1027 — Obfuscated Files or Information",
        "tags": {"obfuscation", "hex-encoded"},
        "yara_hint": "\\x",
    },
    {
        "name": "javascript_obfuscator_identifiers",
        "title": "Dense _0xNNNN identifier run",
        "category": "obfuscation",
        "description": "5+ consecutive _0xNNNN identifiers — javascript-obfuscator default style",
        "severity": "medium", "weight": 1.0,
        "regex": r"(?:_0x[0-9a-fA-F]{4,}[^A-Za-z0-9_]+){5,}",
        "scope": "js",
        "mitre": "T1027 — Obfuscated Files or Information",
        "tags": {"obfuscation", "javascript-obfuscator"},
        "yara_hint": "_0x",
    },
    {
        "name": "decode_uri_hex_literal",
        "title": "decodeURI / decodeURIComponent of %-escaped literal",
        "category": "obfuscation",
        "description": "decodeURI called on a percent-encoded string literal",
        "severity": "medium", "weight": 1.0,
        "regex": r"\b(?:decodeURI|decodeURIComponent)\s*\(\s*['\"]%[0-9a-fA-F]{2}",
        "scope": "js",
        "mitre": "T1027 — Obfuscated Files or Information",
        "tags": {"obfuscation", "url-encoded"},
        "yara_hint": "decodeURIComponent('%",
    },
    {
        "name": "document_write_atob_chain",
        "title": "atob + document.write — multi-stage inline script injection",
        "category": "obfuscation",
        "description": "atob() and document.write() co-occur — decode then inject",
        "severity": "high", "weight": 2.0,
        "all_of": [r"\batob\s*\(", r"document\.write\s*\("],
        "scope": "any",
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"socgholish", "multi-stage"},
        "yara_hint": "document.write(atob(",
    },

    # === FAMILY-ANCHORED =================================================
    {
        "name": "parrot_tds_ndsw_ndsx",
        "title": "Parrot TDS ndsw/ndsx variable convention",
        "category": "infra",
        "description": "Co-occurrence of ndsw + ndsx tokens — historical Parrot TDS convention",
        "severity": "high", "weight": 3.0,
        "all_of": [r"\bndsw\b", r"\bndsx\b"],
        "scope": "any",
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"parrot-tds", "ndsw", "ndsx"},
        "yara_hint": "ndsw",
    },
    {
        "name": "etherhiding_smart_contract_call",
        "title": "ethereum.request + eth_call — EtherHiding-style C2",
        "category": "infra",
        "description": "Page JS reads from a smart contract via ethereum.request/eth_call",
        "severity": "high", "weight": 3.0,
        "all_of": [r"\bethereum\.request\b", r"\beth_call\b"],
        "scope": "any",
        "mitre": "T1102 — Web Service",
        "tags": {"clearfake", "etherhiding", "web3-c2"},
        "yara_hint": "ethereum.request",
    },

    # === REDIRECT / INJECTION ============================================
    {
        "name": "document_write_script_block",
        "title": "document.write of inline <script>",
        "category": "redirect",
        "description": "document.write injecting a <script> element",
        "severity": "high", "weight": 2.5,
        "regex": r"document\.write\s*\(\s*['\"`][^'\"`]*<\s*script\b",
        "scope": "any", "flags": re.IGNORECASE | re.MULTILINE,
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"socgholish", "inline-script", "loader"},
        "yara_hint": "document.write('<script",
    },
    {
        "name": "document_write_external_url",
        "title": "document.write of external script URL",
        "category": "redirect",
        "description": "document.write referencing an external https? JS URL",
        "severity": "high", "weight": 2.5,
        "regex": r"document\.write\s*\(\s*['\"`][^'\"`]*https?://[^'\"`]+\.js",
        "scope": "any", "flags": re.IGNORECASE | re.MULTILINE,
        "mitre": "T1105 — Ingress Tool Transfer",
        "tags": {"socgholish", "external-script", "loader"},
        "yara_hint": "document.write(",
    },
    {
        "name": "dynamic_script_element",
        "title": "createElement('script') — DOM script injection",
        "category": "redirect",
        "description": "JS-created <script> element (typically appended to head/body)",
        "severity": "medium", "weight": 1.0,
        "regex": r"createElement\s*\(\s*['\"]script['\"]\s*\)",
        "scope": "any", "flags": re.IGNORECASE,
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"dynamic-script", "loader"},
        "yara_hint": "createElement('script'",
    },
    {
        "name": "dynamic_iframe_element",
        "title": "createElement('iframe') — DOM iframe injection",
        "category": "redirect",
        "description": "JS-created <iframe> element",
        "severity": "medium", "weight": 1.5,
        "regex": r"createElement\s*\(\s*['\"]iframe['\"]\s*\)",
        "scope": "any", "flags": re.IGNORECASE,
        "mitre": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "tags": {"iframe-injection"},
        "yara_hint": "createElement('iframe'",
    },
    {
        "name": "hidden_iframe_markup",
        "title": "<iframe> sized 1x1 or display:none",
        "category": "redirect",
        "description": "iframe markup with 1x1 dimensions or display:none styling",
        "severity": "medium", "weight": 1.5,
        "regex": r"<iframe[^>]*(?:width\s*=\s*['\"]?[01](?:px)?['\"]?\s+height\s*=\s*['\"]?[01](?:px)?['\"]?|style\s*=\s*['\"][^'\"]*display\s*:\s*none)",
        "scope": "any", "flags": re.IGNORECASE | re.MULTILINE,
        "mitre": "T1189 — Drive-by Compromise",
        "tags": {"iframe-injection", "hidden-frame"},
        "yara_hint": "<iframe",
    },
    {
        "name": "iframe_src_external",
        "title": "<iframe src=https://...>",
        "category": "redirect",
        "description": "Static iframe markup pointing at an external URL",
        "severity": "low", "weight": 0.5,
        "regex": r"<iframe[^>]*src\s*=\s*['\"]https?://",
        "scope": "any", "flags": re.IGNORECASE,
        "mitre": "T1189 — Drive-by Compromise",
        "tags": {"iframe-injection"},
        "yara_hint": "<iframe src=",
    },
    {
        "name": "location_assignment_external",
        "title": "location.* = 'https://...' — JS-driven redirect",
        "category": "redirect",
        "description": "Assignment or call on location with an external https? URL",
        "severity": "medium", "weight": 1.5,
        "regex": r"(?:(?:window|document|top|self)\.)?\blocation(?:\.(?:href|replace|assign))?\s*(?:\(|=)\s*['\"`]https?://",
        "scope": "js",
        "mitre": "T1189 — Drive-by Compromise",
        "tags": {"redirect", "tds"},
        "yara_hint": "location.href = '",
    },
    {
        "name": "window_open_external",
        "title": "window.open('https://...')",
        "category": "redirect",
        "description": "window.open called with an external URL — popup/popunder",
        "severity": "low", "weight": 0.5,
        "regex": r"window\.open\s*\(\s*['\"]https?://",
        "scope": "js",
        "mitre": "T1189 — Drive-by Compromise",
        "tags": {"popunder", "redirect"},
        "yara_hint": "window.open(",
    },
    {
        "name": "meta_refresh_redirect",
        "title": "<meta http-equiv=refresh>",
        "category": "redirect",
        "description": "HTML meta refresh redirect",
        "severity": "low", "weight": 0.5,
        "regex": r"<meta[^>]*http-equiv\s*=\s*['\"]refresh['\"]",
        "scope": "html", "flags": re.IGNORECASE,
        "mitre": "T1189 — Drive-by Compromise",
        "tags": {"meta-refresh"},
        "yara_hint": 'http-equiv="refresh"',
    },
    {
        "name": "fingerprint_then_redirect",
        "title": "navigator inspection + location change in same buffer",
        "category": "redirect",
        "description": "UA/language/platform fingerprint co-occurs with a location change",
        "severity": "high", "weight": 2.0,
        "all_of": [
            r"navigator\.(?:userAgent|language|platform)",
            r"location\.(?:href|replace|assign)\s*(?:=|\()",
        ],
        "scope": "js",
        "mitre": "T1497 — Virtualization/Sandbox Evasion",
        "tags": {"tds", "fingerprint-gate"},
        "yara_hint": "navigator.userAgent",
    },

    # === FINGERPRINTING ==================================================
    {
        "name": "ua_lang_screen_fingerprint",
        "title": "UA + language + screen surface together",
        "category": "fingerprint",
        "description": "Three fingerprint axes in the same buffer — visitor profiling",
        "severity": "medium", "weight": 1.5,
        "all_of": [
            r"navigator\.userAgent",
            r"navigator\.language",
            r"screen\.(?:width|height)",
        ],
        "scope": "js",
        "mitre": "T1497 — Virtualization/Sandbox Evasion",
        "tags": {"fingerprint", "visitor-profile"},
        "yara_hint": "navigator.userAgent",
    },
    {
        "name": "navigator_webdriver_check",
        "title": "navigator.webdriver inspection",
        "category": "fingerprint",
        "description": "navigator.webdriver read — bot/headless detection",
        "severity": "medium", "weight": 1.0,
        "regex": r"\bnavigator\.webdriver\b",
        "scope": "js",
        "mitre": "T1497.001 — Virtualization/Sandbox Evasion: System Checks",
        "tags": {"bot-detection", "headless-check"},
        "yara_hint": "navigator.webdriver",
    },
    {
        "name": "canvas_fingerprint",
        "title": "Canvas 2D + toDataURL — hardware fingerprint",
        "category": "fingerprint",
        "description": "Canvas 2D context paired with toDataURL — hardware fingerprint extraction",
        "severity": "medium", "weight": 1.5,
        "all_of": [
            r"getContext\s*\(\s*['\"]2d['\"]\s*\)",
            r"\.toDataURL\s*\(",
        ],
        "scope": "js",
        "mitre": "T1497 — Virtualization/Sandbox Evasion",
        "tags": {"canvas-fingerprint", "hw-fingerprint"},
        "yara_hint": ".toDataURL(",
    },
    {
        "name": "timezone_fingerprint",
        "title": "Timezone fingerprinting",
        "category": "fingerprint",
        "description": "getTimezoneOffset or Intl.DateTimeFormat.resolvedOptions",
        "severity": "low", "weight": 0.5,
        "regex": r"getTimezoneOffset\s*\(\s*\)|Intl\.DateTimeFormat\s*\(\s*\)\s*\.\s*resolvedOptions",
        "scope": "js",
        "mitre": "T1497 — Virtualization/Sandbox Evasion",
        "tags": {"fingerprint", "geo"},
        "yara_hint": "getTimezoneOffset",
    },
    {
        "name": "visitor_gate_storage",
        "title": "localStorage/cookie + location change — once-per-visitor gating",
        "category": "fingerprint",
        "description": "Storage check paired with a location change",
        "severity": "medium", "weight": 1.5,
        "all_of": [
            r"(?:localStorage\.(?:getItem|setItem)|document\.cookie)",
            r"location\.(?:href|replace|assign)",
        ],
        "scope": "js",
        "mitre": "T1497 — Virtualization/Sandbox Evasion",
        "tags": {"visitor-gate"},
        "yara_hint": "localStorage.getItem(",
    },
    {
        "name": "headless_browser_marker",
        "title": "puppeteer / playwright / HeadlessChrome markers",
        "category": "fingerprint",
        "description": "Direct headless-framework markers",
        "severity": "medium", "weight": 1.0,
        "regex": r"__puppeteer\w*|__playwright|__nightmare|HeadlessChrome",
        "scope": "js",
        "mitre": "T1497.001 — Virtualization/Sandbox Evasion: System Checks",
        "tags": {"headless-check"},
        "yara_hint": "HeadlessChrome",
    },

    # === ANTI-ANALYSIS ===================================================
    {
        "name": "devtools_size_detector",
        "title": "Devtools-open size delta detector",
        "category": "antianalysis",
        "description": "outerHeight/Width - inner check — devtools detection",
        "severity": "medium", "weight": 1.0,
        "regex": r"(?:outerHeight\s*-\s*innerHeight|outerWidth\s*-\s*innerWidth)\s*>\s*\d{2,}",
        "scope": "js",
        "mitre": "T1622 — Debugger Evasion",
        "tags": {"antianalysis", "devtools-check"},
        "yara_hint": "outerHeight - innerHeight",
    },
    {
        "name": "debugger_trap_setInterval",
        "title": "debugger; inside setInterval — debugger stall",
        "category": "antianalysis",
        "description": "Recurring debugger; statement to stall attached debuggers",
        "severity": "medium", "weight": 1.0,
        "regex": r"setInterval\s*\(\s*(?:function[^)]{0,60}|\(\s*\)\s*=>\s*\{)[^}]{0,80}debugger\s*;",
        "scope": "js",
        "mitre": "T1622 — Debugger Evasion",
        "tags": {"antianalysis", "debugger-trap"},
        "yara_hint": "debugger;",
    },
    {
        "name": "anti_keyblock_f12",
        "title": "Blocks F12 / right-click context menu",
        "category": "antianalysis",
        "description": "keyCode 123 (F12) or contextmenu listener — keyboard blocking",
        "severity": "low", "weight": 0.5,
        "regex": r"keyCode\s*===?\s*123\b|addEventListener\s*\(\s*['\"]contextmenu['\"]",
        "scope": "js",
        "mitre": "T1622 — Debugger Evasion",
        "tags": {"antianalysis", "keyblock"},
        "yara_hint": "keyCode === 123",
    },
    {
        "name": "iframe_sandbox_check",
        "title": "window.parent/top != window — iframe context check",
        "category": "antianalysis",
        "description": "Comparing window.top/parent to window — sandbox detection",
        "severity": "low", "weight": 0.5,
        "regex": r"window\.(?:parent|top)\s*!==?\s*window",
        "scope": "js",
        "mitre": "T1497 — Virtualization/Sandbox Evasion",
        "tags": {"antianalysis", "iframe-check"},
        "yara_hint": "window.parent !=",
    },

    # === SOCIAL ENGINEERING ==============================================
    {
        "name": "clickfix_clipboard_writetext",
        "title": "clipboard.writeText + verification lure copy",
        "category": "social_eng",
        "description": "navigator.clipboard.writeText paired with captcha/verify-human lure",
        "severity": "high", "weight": 3.0,
        "all_of": [
            r"navigator\.clipboard\.writeText",
            r"(?:i'?m\s+not\s+a\s+robot|verify\s+you'?re?\s+(?:a\s+)?human|captcha)",
        ],
        "scope": "any", "flags": re.IGNORECASE | re.MULTILINE,
        "mitre": "T1204 — User Execution",
        "tags": {"clickfix", "kongtuke", "clipboard-hijack"},
        "yara_hint": "navigator.clipboard.writeText",
    },
    {
        "name": "exec_command_copy",
        "title": "execCommand('copy') — legacy clipboard write",
        "category": "social_eng",
        "description": "Legacy clipboard-write API",
        "severity": "low", "weight": 0.5,
        "regex": r"execCommand\s*\(\s*['\"]copy['\"]\s*\)",
        "scope": "js",
        "mitre": "T1204 — User Execution",
        "tags": {"clipboard-hijack"},
        "yara_hint": "execCommand('copy')",
    },
    {
        "name": "clearfake_browser_update_lure",
        "title": "Fake browser/Chrome update overlay copy",
        "category": "social_eng",
        "description": "User-facing browser-update lure text",
        "severity": "high", "weight": 2.5,
        "regex": r"update\s+your\s+browser|chrome\s+update|your\s+browser\s+is\s+(?:out\s+of\s+date|outdated)",
        "scope": "any", "flags": re.IGNORECASE | re.MULTILINE,
        "mitre": "T1204 — User Execution",
        "tags": {"clearfake", "socgholish", "fake-update"},
        "yara_hint": "update your browser",
    },

    # === INFRASTRUCTURE / NETWORK ========================================
    {
        "name": "tds_click_tracking_param",
        "title": "TDS-style click-tracking parameter",
        "category": "infra",
        "description": "JS string containing clickid/subid/affid-style TDS params (utm_/gclid excluded — too FP-prone)",
        "severity": "medium", "weight": 1.0,
        "regex": r"['\"`][^'\"`]*[?&](?:clickid|click_id|subid|sub_id|affid|aff_sub|src_id|tds_id)\s*=",
        "scope": "any", "flags": re.IGNORECASE,
        "mitre": "T1102 — Web Service",
        "tags": {"tds", "keitaro", "blacktds"},
        "yara_hint": "clickid=",
    },
    {
        "name": "fetch_external_js_url",
        "title": "fetch('https://...js') — second-stage pull",
        "category": "infra",
        "description": "fetch() pointed at an external .js URL",
        "severity": "medium", "weight": 1.0,
        "regex": r"fetch\s*\(\s*['\"]https?://[^'\"]+\.js",
        "scope": "js",
        "mitre": "T1105 — Ingress Tool Transfer",
        "tags": {"second-stage", "loader"},
        "yara_hint": "fetch('https://",
    },
    {
        "name": "sendBeacon_exfil",
        "title": "navigator.sendBeacon — fire-and-forget telemetry",
        "category": "infra",
        "description": "sendBeacon — common stealth exfil channel",
        "severity": "low", "weight": 0.5,
        "regex": r"navigator\.sendBeacon\s*\(",
        "scope": "js",
        "mitre": "T1041 — Exfiltration Over C2 Channel",
        "tags": {"beacon"},
        "yara_hint": "navigator.sendBeacon(",
    },

    # === CRYPTOJACK ======================================================
    {
        "name": "wasm_compile_instantiate",
        "title": "WebAssembly.compile / instantiate",
        "category": "cryptojack",
        "description": "WASM compile/instantiate — common WASM-miner shape",
        "severity": "high", "weight": 2.0,
        "regex": r"WebAssembly\.(?:compile|instantiate)(?:Streaming)?\s*\(",
        "scope": "js",
        "mitre": "T1496 — Resource Hijacking",
        "tags": {"cryptojack", "wasm"},
        "yara_hint": "WebAssembly.compile",
    },
    {
        "name": "miner_name_marker",
        "title": "Known miner name (xmrig / cryptonight / coinhive / ...)",
        "category": "cryptojack",
        "description": "Explicit reference to a known mining lib/pool",
        "severity": "high", "weight": 2.0,
        "regex": r"\b(?:xmrig|cryptonight|coinhive|coin-hive|jsecoin|cryptoloot|webminerpool|coinimp|minergate)\b",
        "scope": "any", "flags": re.IGNORECASE,
        "mitre": "T1496 — Resource Hijacking",
        "tags": {"cryptojack", "miner"},
        "yara_hint": "xmrig",
    },

    # === PERSISTENCE / ADMIN COMPROMISE ==================================
    {
        "name": "wp_admin_user_create",
        "title": "WordPress wp_create_user / wp_insert_user",
        "category": "persistence",
        "description": "WP admin user creation call — Balada secondary objective",
        "severity": "critical", "weight": 3.0,
        "regex": r"\bwp_(?:create|insert)_user\s*\(",
        "scope": "any",
        "mitre": "T1136.001 — Create Account: Local Account",
        "tags": {"balada-injector", "wordpress", "admin-compromise"},
        "yara_hint": "wp_create_user(",
    },
]


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompiledPattern:
    name: str
    title: str
    category: str
    description: str
    severity: Severity
    weight: float
    scope: str
    primary: re.Pattern
    companions: tuple[re.Pattern, ...]
    is_compound: bool
    mitre: str
    tags: frozenset[str]
    yara_hint: str


def compile_patterns(defs: Sequence[dict[str, Any]]) -> list[CompiledPattern]:
    """Normalize PATTERNS dicts into CompiledPattern; raises on schema errors
    so the module fails fast at import time."""
    out: list[CompiledPattern] = []
    for d in defs:
        flags = d.get("flags", re.MULTILINE)
        scope = d.get("scope", "any")
        if "all_of" in d:
            regs = [re.compile(r, flags) for r in d["all_of"]]
            primary, companions, is_compound = regs[0], tuple(regs[1:]), True
        elif "regex" in d:
            primary, companions, is_compound = re.compile(d["regex"], flags), (), False
        else:
            raise ValueError(
                f"Pattern {d.get('name')!r} requires either 'regex' or 'all_of'"
            )
        out.append(CompiledPattern(
            name=d["name"],
            title=d.get("title", d["name"]),
            category=d["category"],
            description=d.get("description", ""),
            severity=d["severity"],
            weight=float(d["weight"]),
            scope=scope,
            primary=primary,
            companions=companions,
            is_compound=is_compound,
            mitre=d.get("mitre", ""),
            tags=frozenset(d.get("tags", set())),
            yara_hint=d.get("yara_hint", ""),
        ))
    return out


_COMPILED = compile_patterns(PATTERNS)


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

class TriggeredPattern(TypedDict, total=False):
    """Cross-module wire shape. Required fields are the spec'd five; optional
    fields are enrichment forwarded from the pattern definition (consumed by
    the YARA generator when present)."""
    # Required
    pattern_name: str
    severity: str
    snippet: str
    line_range: tuple[int, int]
    source_url: str
    # Optional enrichment
    title: str
    category: str
    description: str
    weight: float
    mitre: str
    tags: list[str]
    yara_hint: str
    entropy_delta: float


class FetchedResource(TypedDict):
    url: str
    sha256: str
    bytes: int
    kind: str  # "html" | "js"


@dataclass
class LLMAssessment:
    verdict: Literal["benign", "suspicious", "malicious"]
    reasoning: str
    model: str


@dataclass
class AnalysisResult:
    domain: str
    fetched_resources: list[FetchedResource]
    triggered_patterns: list[TriggeredPattern]
    composite_score: float
    recommendation: Recommendation
    llm_assessment: Optional[LLMAssessment] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "fetched_resources": list(self.fetched_resources),
            "triggered_patterns": list(self.triggered_patterns),
            "composite_score": round(self.composite_score, 2),
            "recommendation": self.recommendation,
            "llm_assessment": (
                asdict(self.llm_assessment) if self.llm_assessment else None
            ),
        }


# ---------------------------------------------------------------------------
# Fetching layer
# ---------------------------------------------------------------------------

class _ScriptSrcCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.srcs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            src = dict(attrs).get("src")
            if src:
                self.srcs.append(src)


def _strip_leading_www(host: str) -> str:
    return host[4:] if host.lower().startswith("www.") else host


def _registrable(host: str) -> str:
    """Approximate registrable domain — last two labels of the stripped host.
    Not a Public Suffix List substitute; for corpora with `co.uk`-style TLDs
    swap in `tldextract`."""
    parts = _strip_leading_www(host.lower()).split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _is_first_party(url: str, root_host: str) -> bool:
    host = urlparse(url).netloc
    if not host:
        return True
    return _registrable(host) == _registrable(root_host)


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fetch_domain(
    domain: str,
    *,
    max_scripts: int = DEFAULT_MAX_SCRIPTS,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    user_agent: str = DEFAULT_USER_AGENT,
) -> list[tuple[FetchedResource, str]]:
    """Fetch homepage + first-party <script src> contents.

    Returns [(resource_metadata, content), ...]. First entry is always the
    homepage HTML; subsequent entries are JS resources up to max_scripts.
    """
    base = domain if "://" in domain else f"https://{domain.lstrip('/')}"
    headers = {"User-Agent": user_agent, "Accept": "text/html,*/*;q=0.8"}
    out: list[tuple[FetchedResource, str]] = []

    with httpx.Client(follow_redirects=True, timeout=timeout_s,
                      headers=headers) as client:
        r = client.get(base)
        r.raise_for_status()
        html = r.text
        out.append((
            FetchedResource(
                url=str(r.url),
                sha256=_sha256(html.encode("utf-8", "replace")),
                bytes=len(html),
                kind="html",
            ),
            html,
        ))

        coll = _ScriptSrcCollector()
        coll.feed(html)

        root_host = urlparse(str(r.url)).netloc
        seen_lc: set[str] = set()
        for src in coll.srcs:
            if len(out) - 1 >= max_scripts:
                break
            if src.startswith("data:"):
                continue
            absurl = urljoin(str(r.url), src)
            # Dedup by lowercased key, but fetch the original-cased URL —
            # some servers serve case-sensitive paths.
            key = absurl.lower().rstrip("/")
            if key in seen_lc:
                continue
            seen_lc.add(key)
            if not _is_first_party(absurl, root_host):
                continue
            try:
                jr = client.get(absurl)
            except httpx.HTTPError:
                continue
            if jr.status_code != 200:
                continue
            content = jr.text[:MAX_RESOURCE_BYTES]
            out.append((
                FetchedResource(
                    url=str(jr.url),
                    sha256=_sha256(content.encode("utf-8", "replace")),
                    bytes=len(content),
                    kind="js",
                ),
                content,
            ))
    return out


# ---------------------------------------------------------------------------
# Deterministic analysis
# ---------------------------------------------------------------------------

_WS_RUN = re.compile(r"[ \t]+")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _line_range(text: str, start: int, end: int) -> tuple[int, int]:
    pre = text[:start].count("\n") + 1
    return (pre, pre + text[start:end].count("\n"))


def _snippet(text: str, start: int, end: int) -> str:
    lo = max(0, start - SNIPPET_RADIUS)
    hi = min(len(text), end + SNIPPET_RADIUS)
    s = _WS_RUN.sub(" ", text[lo:hi]).strip()
    return s if len(s) <= SNIPPET_MAX_CHARS else s[: SNIPPET_MAX_CHARS - 1] + "…"


def _build_triggered(
    pat: CompiledPattern,
    text: str,
    source_url: str,
    matches: list[re.Match],
) -> list[TriggeredPattern]:
    out: list[TriggeredPattern] = []
    for m in matches:
        tp: TriggeredPattern = {
            "pattern_name": pat.name,
            "severity": pat.severity,
            "snippet": _snippet(text, m.start(), m.end()),
            "line_range": _line_range(text, m.start(), m.end()),
            "source_url": source_url,
            "title": pat.title,
            "category": pat.category,
            "description": pat.description,
            "weight": pat.weight,
            "mitre": pat.mitre,
            "tags": sorted(pat.tags),
            "yara_hint": pat.yara_hint,
        }
        out.append(tp)
    return out


def _apply_pattern(
    pat: CompiledPattern, text: str, kind: str, source_url: str,
) -> list[TriggeredPattern]:
    if pat.scope != "any" and pat.scope != kind:
        return []
    matches = list(pat.primary.finditer(text))
    if not matches:
        return []
    if pat.is_compound:
        for c in pat.companions:
            if not c.search(text):
                return []
    return _build_triggered(pat, text, source_url, matches)


# Structural checks — return (triggered_list, score_delta).
StructuralCheck = Callable[
    [str, str, str], tuple[list[TriggeredPattern], float]
]


def _check_entropy_delta(
    text: str, kind: str, source_url: str,
) -> tuple[list[TriggeredPattern], float]:
    """Flag high-entropy blocks sitting inside an otherwise low-entropy file.
    Catches append-style injects without relying on the inject's exact shape."""
    if kind != "js" or len(text) < 4000:
        return [], 0.0
    lines = text.splitlines(keepends=True)
    if len(lines) < 40:
        return [], 0.0
    block = max(40, len(lines) // 20)
    blocks: list[tuple[int, int, str, float]] = []
    for i in range(0, len(lines), block):
        chunk = "".join(lines[i:i + block])
        if len(chunk) < 200:
            continue
        blocks.append((
            i + 1, min(i + block, len(lines)), chunk, _shannon_entropy(chunk),
        ))
    if not blocks:
        return [], 0.0
    median = sorted(b[3] for b in blocks)[len(blocks) // 2]
    hits: list[TriggeredPattern] = []
    for lo, hi, chunk, ent in blocks:
        if ent > 5.0 and ent - median > 0.8:
            snippet_text = _WS_RUN.sub(" ", chunk[:SNIPPET_MAX_CHARS]).strip()
            if len(chunk) > SNIPPET_MAX_CHARS:
                snippet_text += "…"
            hits.append({
                "pattern_name": "entropy_delta_block",
                "severity": "medium",
                "snippet": snippet_text,
                "line_range": (lo, hi),
                "source_url": source_url,
                "title": "High-entropy block in low-entropy file",
                "category": "obfuscation",
                "description": (
                    f"Block entropy {ent:.2f} vs file median {median:.2f}"
                ),
                "weight": 1.5,
                "mitre": "T1027 — Obfuscated Files or Information",
                "tags": ["obfuscation", "entropy-delta"],
                "yara_hint": "",
                "entropy_delta": round(ent - median, 3),
            })
    return hits, (1.5 if hits else 0.0)


def _check_single_line_inject(
    text: str, kind: str, source_url: str,
) -> tuple[list[TriggeredPattern], float]:
    """First or last non-blank line in a JS file is unusually long AND contains
    an obfuscation marker — the canonical appended-inject shape."""
    if kind != "js":
        return [], 0.0
    lines = [(i + 1, ln) for i, ln in enumerate(text.splitlines()) if ln.strip()]
    if not lines:
        return [], 0.0
    markers = ("eval(", "atob(", "Function(", "_0x", "ndsw", "ndsx")
    hits: list[TriggeredPattern] = []
    seen_lines: set[int] = set()
    for idx in (0, -1):
        line_no, line = lines[idx]
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        if len(line) > 400 and any(m in line for m in markers):
            snippet_text = _WS_RUN.sub(" ", line[:SNIPPET_MAX_CHARS]).strip()
            if len(line) > SNIPPET_MAX_CHARS:
                snippet_text += "…"
            hits.append({
                "pattern_name": "single_line_inject",
                "severity": "high",
                "snippet": snippet_text,
                "line_range": (line_no, line_no),
                "source_url": source_url,
                "title": "Long single-line inject at file boundary",
                "category": "obfuscation",
                "description": (
                    "First/last non-blank line > 400 chars contains an "
                    "obfuscation marker — typical of appended injects"
                ),
                "weight": 2.0,
                "mitre": "T1027 — Obfuscated Files or Information",
                "tags": ["socgholish", "parrot-tds", "inject-shape"],
                "yara_hint": "",
            })
    return hits, (2.0 if hits else 0.0)


STRUCTURAL_CHECKS: list[StructuralCheck] = [
    _check_entropy_delta,
    _check_single_line_inject,
]


def _analyze_buffer(
    text: str, kind: str, source_url: str,
) -> tuple[list[TriggeredPattern], float]:
    """Apply every pattern + every structural check to one buffer. Score adds
    a pattern's weight once per source (not per match — that double-counted in
    the prior draft). Per-category cap dampens pile-on from one noisy block."""
    triggered: list[TriggeredPattern] = []
    cat_counts: Counter[str] = Counter()
    score = 0.0

    for pat in _COMPILED:
        hits = _apply_pattern(pat, text, kind, source_url)
        if not hits:
            continue
        triggered.extend(hits)
        if cat_counts[pat.category] < PER_CATEGORY_CAP:
            score += pat.weight
        else:
            score += pat.weight * DAMPENED_WEIGHT_FACTOR
        cat_counts[pat.category] += 1

    for fn in STRUCTURAL_CHECKS:
        hits, delta = fn(text, kind, source_url)
        triggered.extend(hits)
        score += delta

    return triggered, score


# ---------------------------------------------------------------------------
# LLM escalation
# ---------------------------------------------------------------------------

class LLMClient(Protocol):
    """Plug-in interface. Implement `assess` against whatever model you trust."""
    def assess(
        self,
        domain: str,
        triggered: Sequence[TriggeredPattern],
        score: float,
    ) -> LLMAssessment: ...


def build_escalation_prompt(
    domain: str,
    triggered: Sequence[TriggeredPattern],
    score: float,
) -> str:
    """Reusable prompt builder for ad-hoc LLMClient implementations."""
    lines = [
        "=== CRUCIBLE JS COMPROMISE ESCALATION ===",
        f"Domain: {domain}",
        f"Composite score: {score:.2f} (LLM band: {LLM_BAND[0]}–{LLM_BAND[1]})",
        f"Triggered patterns: {len(triggered)}",
        "",
        "--- TRIGGERED ---",
    ]
    for i, tp in enumerate(triggered, 1):
        lines.append(f"\n[{i}] {tp.get('pattern_name','?')} "
                     f"({tp.get('severity','?')})")
        lines.append(f"    title:   {tp.get('title','')}")
        lines.append(f"    source:  {tp.get('source_url','')}")
        lines.append(f"    lines:   {tp.get('line_range','')}")
        if tp.get("mitre"):
            lines.append(f"    mitre:   {tp['mitre']}")
        if tp.get("tags"):
            lines.append(f"    tags:    {', '.join(tp['tags'])}")
        lines.append(f"    snippet: {tp.get('snippet','')}")
    lines.append(
        "\nDecide whether this domain is serving malicious traffic-distribution JS. "
        "Reply with one of {benign, suspicious, malicious} plus a one-sentence rationale."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _recommend(score: float, llm: Optional[LLMAssessment]) -> Recommendation:
    if score >= LLM_BAND[1]:
        return "likely_compromised"
    if score < LLM_BAND[0]:
        return "likely_clean"
    if llm is None:
        return "suspicious"
    if llm.verdict == "malicious":
        return "likely_compromised"
    if llm.verdict == "benign":
        return "likely_clean"
    return "suspicious"


def analyze_domain(
    domain: str,
    *,
    prefetched: Optional[Sequence[tuple[FetchedResource, str]]] = None,
    max_scripts: int = DEFAULT_MAX_SCRIPTS,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    user_agent: str = DEFAULT_USER_AGENT,
    llm: Optional[LLMClient] = None,
) -> AnalysisResult:
    """Analyze a domain for JS compromise indicators.

    Args:
        domain: bare domain ("example.com") or URL.
        prefetched: optional (FetchedResource, content) tuples — skips the
            network fetch entirely (offline replay, VT-captured submissions).
        max_scripts / timeout_s / user_agent: forwarded to fetch_domain.
        llm: optional LLMClient. Invoked only when composite_score falls in
            LLM_BAND. Pass None to disable escalation.
    """
    if prefetched is None:
        fetched = fetch_domain(
            domain,
            max_scripts=max_scripts,
            timeout_s=timeout_s,
            user_agent=user_agent,
        )
    else:
        fetched = list(prefetched)

    triggered: list[TriggeredPattern] = []
    score = 0.0
    for res, content in fetched:
        hits, sub = _analyze_buffer(content, res["kind"], res["url"])
        triggered.extend(hits)
        score += sub

    llm_assessment: Optional[LLMAssessment] = None
    if llm is not None and LLM_BAND[0] <= score < LLM_BAND[1]:
        llm_assessment = llm.assess(domain, triggered, score)

    return AnalysisResult(
        domain=domain,
        fetched_resources=[r for r, _ in fetched],
        triggered_patterns=triggered,
        composite_score=round(score, 2),
        recommendation=_recommend(score, llm_assessment),
        llm_assessment=llm_assessment,
    )

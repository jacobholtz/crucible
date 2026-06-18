"""
crucible.yara_retrohunt_generator
=================================

Generates VirusTotal retrohunt-compatible YARA rules from the triggered_patterns
output of crucible.js_compromise_detector.

Retrohunt constraints baked into the design:
  * Matches are against file contents at submission time (mostly scraped
    HTML/JS captures). Rules must be cheap — literal strings preferred,
    unbounded regex avoided.
  * Every rule requires at least two distinct strings, OR one string plus a
    structural condition (filesize / negative anchors). No single-string rules.
  * False positives have high cost. Each candidate literal is sanity-checked
    against a small library of legitimate-JS fingerprints (jQuery, React, GA,
    GTM, fb-pixel, Cloudflare, Stripe, Intercom). Overlapping candidates are
    dropped and re-added as negative anchors on the loose variant.

For each input pattern (or family group) the generator emits two rules:

  <name>_tight    strict, campaign-specific — requires >= 2 campaign literals.
  <name>_loose    behavioral — literals + behavioral tokens + structural anchor;
                  includes negative anchors when FP overlap was detected.

Module 1 integration
--------------------
This module recognizes the optional enrichment fields produced by
js_compromise_detector:

  * `yara_hint`  — curated anchor literal, prepended to the candidate list
                   (still subject to the FP sanity check).
  * `tags`       — used to infer the family slug for rule-name prefixing
                   when no explicit `family_hint` is passed.
  * `mitre`      — written into rule meta.
  * `category`   — used as a name-prefix fallback when no family is known.
  * `title`      — written into rule meta as `pattern_title`.

All optional. The generator works on a minimal triggered_patterns dict
(`pattern_name`, `severity`, `snippet`, `line_range`, `source_url`) — the
enrichment fields just make the output richer.

Public surface
--------------
  generate_retrohunt_rules(patterns, family_hint=None, **kw) -> GeneratorResult
"""

from __future__ import annotations

import datetime as _dt
import hashlib as _hashlib
import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence, TypedDict
from urllib.parse import urlparse


Confidence = Literal["low", "medium", "high"]
Variant = Literal["tight", "loose"]
VolumeEstimate = Literal["low", "medium", "high"]


class ManifestEntry(TypedDict):
    variant: Variant
    expected_volume_estimate: VolumeEstimate
    review_notes: list[str]
    confidence: Confidence
    source_pattern: str


@dataclass
class GeneratorResult:
    rules_text: str
    manifest: dict[str, ManifestEntry]
    report: list[str]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_HEX_IDENT_RE = re.compile(r"_0x[0-9a-fA-F]{4,}")
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_BLOB_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}")
_URL_RE = re.compile(r"https?://[^\s'\"`<>]+")
_RANDOM_TOKEN_RE = re.compile(r"\b[A-Za-z0-9]{16,}\b")
_STR_LITERAL_RE = re.compile(r"""(['"])((?:\\.|(?!\1).){4,})\1""")


def _short(s: str, n: int = 40) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _normalize_snippet(snippet: str) -> tuple[str, list[str]]:
    """Strip campaign-specific identifiers (obfuscator hex idents, URLs, b64
    blobs, hex blobs, high-entropy random tokens). Returns (normalized_text,
    notes) — each note records one generalization decision so the auditor can
    see what the rule gave up."""
    notes: list[str] = []
    out = re.sub(r"[ \t]+", " ", snippet)

    if _HEX_IDENT_RE.search(out):
        out = _HEX_IDENT_RE.sub("__IDENT__", out)
        notes.append(
            "Replaced javascript-obfuscator hex identifiers (_0xNNNN) — "
            "build-specific, rotate per generation"
        )
    for url in set(_URL_RE.findall(out)):
        out = out.replace(url, "__URL__")
        notes.append(
            f"Stripped URL literal ({_short(url)}) — second-stage domains rotate"
        )
    if _B64_BLOB_RE.search(out):
        out = _B64_BLOB_RE.sub("__B64__", out)
        notes.append("Replaced base64-like blob with __B64__ (payload-specific)")
    if _HEX_BLOB_RE.search(out):
        out = _HEX_BLOB_RE.sub("__HEXBLOB__", out)
        notes.append("Replaced \\xNN escape blob with __HEXBLOB__")
    if _RANDOM_TOKEN_RE.search(out):
        out = _RANDOM_TOKEN_RE.sub("__TOKEN__", out)
        notes.append("Replaced 16+ char high-entropy tokens with __TOKEN__")

    return out, notes


# ---------------------------------------------------------------------------
# Literal extraction
# ---------------------------------------------------------------------------

_BLACKLIST_LITERALS = {
    "function", "return", "var", "let", "const", "if", "else", "true",
    "false", "null", "undefined", "this", "window", "document", "console",
    "log", "data", "value", "name", "type", "length", "push", "call",
    "apply", "bind", "prototype", "string", "number", "object",
}

# Behavioral surface strings worth using as structural anchors but never on
# their own — too generic.
_BEHAVIORAL_TOKENS = [
    "navigator.userAgent",
    "navigator.webdriver",
    "navigator.language",
    "navigator.platform",
    "navigator.clipboard.writeText",
    "navigator.sendBeacon",
    "screen.width",
    "screen.height",
    "Intl.DateTimeFormat",
    "getTimezoneOffset",
    "document.write",
    "atob(",
    "eval(",
    "Function(",
    "location.href",
    "location.replace",
    "location.assign",
    "localStorage",
    "document.cookie",
    "createElement('script')",
    'createElement("script")',
    "createElement('iframe')",
    'createElement("iframe")',
    "WebAssembly.compile",
    "WebAssembly.instantiate",
    "ethereum.request",
    "eth_call",
]


def _extract_literals(normalized: str) -> list[str]:
    raw = [m.group(2) for m in _STR_LITERAL_RE.finditer(normalized)]
    keep: list[str] = []
    seen: set[str] = set()
    for s in raw:
        s = s.strip()
        if (
            len(s) >= 5
            and s.lower() not in _BLACKLIST_LITERALS
            and "__" not in s        # already-stripped placeholder
            and s not in seen
        ):
            keep.append(s)
            seen.add(s)
    return keep


def _extract_behavioral(normalized: str) -> list[str]:
    return [tok for tok in _BEHAVIORAL_TOKENS if tok in normalized]


# ---------------------------------------------------------------------------
# Family inference (uses Module 1's `tags` enrichment)
# ---------------------------------------------------------------------------

# (tag → family slug). First matching tag wins. The slug becomes the rule-name
# prefix when family_hint isn't provided explicitly.
_FAMILY_TAGS: tuple[tuple[str, str], ...] = (
    ("parrot-tds", "parrot_tds"),
    ("ndsw", "parrot_tds"),
    ("ndsx", "parrot_tds"),
    ("socgholish", "socgholish"),
    ("fake-update", "socgholish"),
    ("balada-injector", "balada"),
    ("clearfake", "clearfake"),
    ("etherhiding", "etherhiding"),
    ("kongtuke", "kongtuke"),
    ("clickfix", "clickfix"),
    ("clipboard-hijack", "clickfix"),
    ("keitaro", "keitaro_tds"),
    ("blacktds", "blacktds"),
    ("cryptojack", "cryptojack"),
    ("wasm", "cryptojack"),
)


def _infer_family(pattern: Mapping[str, Any]) -> str | None:
    tag_set = {str(t).lower() for t in (pattern.get("tags") or [])}
    for tag, family in _FAMILY_TAGS:
        if tag in tag_set:
            return family
    return None


# ---------------------------------------------------------------------------
# Legitimate-JS fingerprints (FP sanity check)
# ---------------------------------------------------------------------------

_LEGIT_FINGERPRINTS: dict[str, list[str]] = {
    "jquery":     ["jQuery", "jquery.com", "fn.jquery", "noConflict"],
    "react":      ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "react-dom", "useEffect"],
    "ga_gtm":     ["googletagmanager.com", "google-analytics.com",
                   "gtag(", "GoogleAnalyticsObject"],
    "fb_pixel":   ["fbq(", "connect.facebook.net", "facebook.com/tr"],
    "cloudflare": ["cdnjs.cloudflare.com", "challenges.cloudflare.com"],
    "stripe":     ["js.stripe.com", "Stripe(", "stripe.elements"],
    "intercom":   ["widget.intercom.io", "Intercom("],
}


def _legit_overlap(literal: str) -> list[str]:
    hits: list[str] = []
    low = literal.lower()
    for family, fps in _LEGIT_FINGERPRINTS.items():
        for fp in fps:
            if fp.lower() in low or low in fp.lower():
                hits.append(family)
                break
    return hits


# ---------------------------------------------------------------------------
# Rule emission
# ---------------------------------------------------------------------------

_RULE_TEMPLATE = """\
rule {name}
{{
    meta:
        author          = "{author}"
        date            = "{date}"
        description     = "{description}"
        source_domain   = "{source_domain}"
        source_pattern  = "{source_pattern}"
        confidence      = "{confidence}"
        variant         = "{variant}"
        reference       = "{reference}"
{extra_meta}    strings:
{strings_block}
    condition:
        {condition}
}}
"""

_DEFAULT_STRUCTURAL = "filesize < 500KB"


def _yara_escape(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\r", "\\r")
    )


def _rule_name(family: str | None, pattern_name: str, variant: Variant) -> str:
    fam = re.sub(r"[^a-z0-9]+", "_",
                 (family or "behavior").lower()).strip("_") or "behavior"
    pn = re.sub(r"[^a-z0-9]+", "_",
                pattern_name.lower()).strip("_") or "pattern"
    # Drop the family prefix from pattern_name if it's already there — avoids
    # crucible_js_parrot_tds_parrot_tds_ndsw_ndsx style duplication.
    if pn.startswith(fam + "_"):
        pn = pn[len(fam) + 1:]
    h = _hashlib.sha1(f"{fam}/{pn}/{variant}".encode()).hexdigest()[:6]
    return f"crucible_js_{fam}_{pn}_{variant}_{h}"


def _format_extra_meta(extras: dict[str, str]) -> str:
    if not extras:
        return ""
    return "\n".join(
        f'        {k:<15} = "{_yara_escape(v)}"' for k, v in extras.items()
    ) + "\n"


def _emit_rule(
    *,
    name: str,
    description: str,
    source_domain: str,
    source_pattern: str,
    confidence: Confidence,
    variant: Variant,
    reference: str,
    author: str,
    extra_meta: dict[str, str],
    string_literals: Sequence[str],
    behavioral_tokens: Sequence[str],
    negative_anchors: Sequence[str],
    structural_clause: str | None,
    min_match: int,
) -> str:
    lines: list[str] = []
    for i, lit in enumerate(string_literals):
        lines.append(f'        $s{i} = "{_yara_escape(lit)}" ascii')
    for i, tok in enumerate(behavioral_tokens):
        lines.append(f'        $b{i} = "{_yara_escape(tok)}" ascii')
    for i, neg in enumerate(negative_anchors):
        lines.append(f'        $neg{i} = "{_yara_escape(neg)}" ascii nocase')

    sig = [f"$s{i}" for i in range(len(string_literals))] + \
          [f"$b{i}" for i in range(len(behavioral_tokens))]
    neg = [f"$neg{i}" for i in range(len(negative_anchors))]

    parts: list[str] = [f"{min_match} of ({', '.join(sig)})"]
    if structural_clause:
        parts.append(structural_clause)
    if neg:
        parts.append(f"not any of ({', '.join(neg)})")
    condition = " and\n        ".join(parts)

    return _RULE_TEMPLATE.format(
        name=name,
        author=author,
        date=_dt.date.today().isoformat(),
        description=_yara_escape(description),
        source_domain=_yara_escape(source_domain),
        source_pattern=_yara_escape(source_pattern),
        confidence=confidence,
        variant=variant,
        reference=_yara_escape(reference),
        extra_meta=_format_extra_meta(extra_meta),
        strings_block="\n".join(lines),
        condition=condition,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_retrohunt_rules(
    patterns: Sequence[Mapping[str, Any]],
    family_hint: str | None = None,
    *,
    author: str = "crucible",
    reference: str = "",
) -> GeneratorResult:
    """Generate tight + loose retrohunt YARA rules for each triggered pattern.

    Args:
        patterns: triggered_patterns entries from the analyzer. Required keys:
            pattern_name, severity, snippet, line_range, source_url. Optional:
            title, category, mitre, tags, yara_hint.
        family_hint: family slug for rule-name prefix. If None, the generator
            infers per-pattern from `tags` (parrot-tds → parrot_tds, etc.);
            falls back to the pattern's `category`; finally to "behavior".
        author / reference: forwarded into rule meta.
    """
    rules_text_parts: list[str] = []
    manifest: dict[str, ManifestEntry] = {}
    report: list[str] = []

    for pat in patterns:
        snippet = pat.get("snippet") or ""
        pattern_name = pat.get("pattern_name", "unknown")
        severity = (pat.get("severity") or "medium").lower()
        source_url = pat.get("source_url", "")
        source_domain = urlparse(source_url).netloc if source_url else ""
        yara_hint = (pat.get("yara_hint") or "").strip()
        mitre = pat.get("mitre") or ""
        title = pat.get("title") or pattern_name
        category = pat.get("category") or ""

        family = family_hint or _infer_family(pat) or category or None

        normalized, notes = _normalize_snippet(snippet)
        literals = _extract_literals(normalized)
        behavioral = _extract_behavioral(normalized)

        # yara_hint, if present, is a curated anchor from Module 1's pattern
        # definition. Treat it as a high-priority $s candidate, still subject
        # to the FP sanity check below.
        if yara_hint and yara_hint not in literals:
            literals.insert(0, yara_hint)

        if not literals and not behavioral:
            report.append(
                f"[skip] {pattern_name}: no usable signals after normalization"
            )
            continue

        # Per-literal FP sanity check
        fp_hits: list[str] = []
        safe_literals: list[str] = []
        for lit in literals:
            hits = _legit_overlap(lit)
            if hits:
                fp_hits.extend(hits)
                notes.append(
                    f"Dropped literal {_short(lit)!r} — overlaps {','.join(hits)}"
                )
            else:
                safe_literals.append(lit)

        if severity in ("critical", "high") and len(safe_literals) >= 2:
            confidence: Confidence = "high"
        elif severity == "low" or not safe_literals:
            confidence = "low"
        else:
            confidence = "medium"

        extra_meta_common: dict[str, str] = {}
        if mitre:
            extra_meta_common["mitre"] = mitre
        if title and title != pattern_name:
            extra_meta_common["pattern_title"] = title
        tag_strs = [str(t) for t in (pat.get("tags") or [])]
        if tag_strs:
            extra_meta_common["pattern_tags"] = ", ".join(tag_strs)

        # -- tight ----------------------------------------------------------
        if len(safe_literals) >= 2:
            name = _rule_name(family, pattern_name, "tight")
            rules_text_parts.append(_emit_rule(
                name=name,
                description=(
                    f"Tight match for {pattern_name}"
                    + (f" observed on {source_domain}" if source_domain else "")
                ),
                source_domain=source_domain,
                source_pattern=pattern_name,
                confidence=confidence,
                variant="tight",
                reference=reference,
                author=author,
                extra_meta=extra_meta_common,
                string_literals=safe_literals[:6],
                behavioral_tokens=behavioral[:3],
                negative_anchors=[],
                structural_clause=_DEFAULT_STRUCTURAL,
                min_match=2,
            ))
            vol: VolumeEstimate = "low" if len(safe_literals) >= 3 else "medium"
            manifest[name] = {
                "variant": "tight",
                "expected_volume_estimate": vol,
                "review_notes": list(notes),
                "confidence": confidence,
                "source_pattern": pattern_name,
            }
            report.append(
                f"[tight] {name} — {len(safe_literals)} literals, vol={vol}"
            )
        else:
            report.append(
                f"[no-tight] {pattern_name}: only {len(safe_literals)} safe "
                f"literal(s); tight variant requires >=2"
            )

        # -- loose ----------------------------------------------------------
        loose_strings = safe_literals[:2]
        loose_behavioral = behavioral[:4]
        if (len(loose_strings) + len(loose_behavioral)) < 2:
            report.append(
                f"[no-loose] {pattern_name}: <2 total signals; skipping"
            )
            continue

        loose_negative: list[str] = []
        if fp_hits:
            seen: set[str] = set()
            for fam in fp_hits:
                for fp in _LEGIT_FINGERPRINTS.get(fam, []):
                    if fp not in seen:
                        loose_negative.append(fp)
                        seen.add(fp)

        loose_conf: Confidence = "low" if confidence == "high" else confidence
        loose_notes = list(notes)
        if fp_hits:
            loose_notes.append(
                f"FP sanity-check flagged {sorted(set(fp_hits))}; "
                f"added negative anchors"
            )
        if not loose_strings:
            loose_notes.append(
                "No campaign-specific literals survived — rule is purely "
                "behavioral; manual review recommended before submission"
            )

        name = _rule_name(family, pattern_name, "loose")
        rules_text_parts.append(_emit_rule(
            name=name,
            description=f"Behavioral pattern for {pattern_name} (variant discovery)",
            source_domain=source_domain,
            source_pattern=pattern_name,
            confidence=loose_conf,
            variant="loose",
            reference=reference,
            author=author,
            extra_meta=extra_meta_common,
            string_literals=loose_strings,
            behavioral_tokens=loose_behavioral,
            negative_anchors=loose_negative,
            structural_clause=_DEFAULT_STRUCTURAL,
            min_match=2,
        ))

        loose_vol: VolumeEstimate = (
            "high" if not loose_strings and not loose_negative
            else "medium" if not loose_negative
            else "low"
        )
        manifest[name] = {
            "variant": "loose",
            "expected_volume_estimate": loose_vol,
            "review_notes": loose_notes,
            "confidence": loose_conf,
            "source_pattern": pattern_name,
        }
        report.append(
            f"[loose] {name} — vol={loose_vol}, "
            f"neg_anchors={len(loose_negative)}"
        )

    return GeneratorResult(
        rules_text="\n".join(rules_text_parts),
        manifest=manifest,
        report=report,
    )

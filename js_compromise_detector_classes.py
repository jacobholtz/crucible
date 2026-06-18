# ============================================================================
# Public data classes for integration
# ============================================================================


@dataclass
class JSDetectionEvent:
    """A single triggered detection event."""
    pattern_name: str
    pattern_title: str
    severity: str
    category: str
    weight: int
    description: str
    matched_line: str
    line_number: int
    mitre: str
    tags: set[str]
    snippet: str


@dataclass
class JSDetectionResult:
    """Container for the full detection outcome."""
    domain: str
    events: list[JSDetectionEvent]
    composite_score: float
    recommendation: str
    is_clean: bool
    is_compromised: bool
    ambiguous: bool
    triggered_categories: set[str]
    matched_mitre_techniques: set[str]


# ============================================================================
# Main detector class
# ============================================================================


class JSDetector:
    """
    High-level interface for the static JS compromise detector.

    Usage:
        detector = JSDetector()
        result = detector.analyze_js_content(source_code)
        # or
        result = detector.analyze_domain(domain)
    """

    def __init__(
        self,
        domain: Optional[str] = None,
        score_thresholds: Optional[dict[str, int]] = None,
        max_js_files: int = DEFAULT_JS_CAP,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.domain = domain
        self.score_thresholds = score_thresholds or DEFAULT_SCORE_THRESHOLDS
        self.max_js_files = max_js_files
        self.timeout = timeout
        self._PATTERNS = PATTERNS

    def analyze_js_content(self, source_code: str, url: Optional[str] = None) -> JSDetectionResult:
        """Analyze a single JS source string for compromise indicators."""
        triggered = _match_patterns_in_resource(source_code, self._PATTERNS, url)
        score = _compute_composite_score(triggered)
        recommendation = _determine_recommendation(score)
        is_clean = score < self.score_thresholds["clean_min"]
        is_compromised = score >= self.score_thresholds["compromised_min"]

        # Build JSDetectionEvent objects
        events: list[JSDetectionEvent] = []
        for tp in triggered:
            evt = JSDetectionEvent(
                pattern_name=tp.pattern["name"],
                pattern_title=tp.pattern["title"],
                severity=tp.pattern["severity"],
                category=tp.pattern["category"],
                weight=tp.pattern["weight"],
                description=tp.description,
                matched_line=tp.matched_line.strip()[:MAX_SNIPPET_CHARS],
                line_number=tp.line_number,
                mitre=tp.pattern.get("mitre", "Unknown"),
                tags=tp.pattern.get("tags", set()),
                snippet=tp.matched_line.strip()[:100],
            )
            events.append(evt)

        triggered_cats = {tp.pattern["category"] for tp in triggered}
        mitre_techs = {tp.pattern.get("mitre", "").split(" \u2014 ")[0] for tp in triggered if tp.pattern.get("mitre")}

        # Build JSDetectionResult
        result = JSDetectionResult(
            domain=self.domain or "unknown",
            events=events,
            composite_score=score,
            recommendation=recommendation,
            is_clean=is_clean,
            is_compromised=is_compromised,
            ambiguous=not is_clean and not is_compromised,
            triggered_categories=triggered_cats,
            matched_mitre_techniques=mitre_techs,
        )
        return result

    async def analyze_domain(self, domain: str, max_js_files: Optional[int] = None, timeout: Optional[int] = None) -> JSDetectionResult:
        """
        Fetch all first-party .js resources for a domain and analyze them.

        Returns JSDetectionResult containing all matched patterns and a composite score.
        """
        max_js = max_js_files or self.max_js_files
        to_fetch = await fetch_resources(domain, max_js, timeout or self.timeout)
        if not to_fetch or not to_fetch.resources:
            # Nothing to analyze
            return JSDetectionResult(
                domain=domain,
                events=[],
                composite_score=0.0,
                recommendation="NO_DATA",
                is_clean=True,
                is_compromised=False,
                ambiguous=False,
                triggered_categories=set(),
                matched_mitre_techniques=set(),
            )

        # Analyze each resource
        all_events: list[TriggeredPattern] = []
        for res in to_fetch.resources:
            if res.fetch_error:
                continue
            triggered = _match_patterns_in_resource(res.content, self._PATTERNS, res.url)
            all_events.extend(triggered)

        if not all_events:
            return JSDetectionResult(
                domain=domain,
                events=[],
                composite_score=0.0,
                recommendation="NO_DATA",
                is_clean=True,
                is_compromised=False,
                ambiguous=False,
                triggered_categories=set(),
                matched_mitre_techniques=set(),
            )

        # Use analyze_js_content for final aggregation
        return self.analyze_js_content("\n".join(r.content for r in to_fetch.resources if not r.fetch_error))

    def find_jss(self, html: str) -> list[str]:
        """Extract first-party .js URLs from an HTML document."""
        return _extract_js_urls(html, self.domain or "", self.max_js_files)

"""
Multi-Platform IOC Correlation Engine for CRUCIBLE SIGINT v5.1
Cross-reference discovered IOCs with VirusTotal, AlienVault OTX, URLHaus,
identify when domains appear in multiple threat feeds simultaneously,
and create weighted confidence scoring based on feed consensus.
"""

import asyncio
import httpx
import os
import json
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter


class IOCCorrelationEngine:
    """Multi-platform IOC correlation engine"""
    
    def __init__(self):
        # Initialize with API keys from environment
        self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.alienvault_api_key = os.environ.get("ALIENVAULT_API_KEY", "")
        
        # Define weights for different threat feeds
        # Higher weights indicate higher confidence in the feed
        self.feed_weights = {
            "virustotal": 0.35,
            "alienvault_otx": 0.30,
            "urlhaus": 0.25,
            "internal_correlation": 0.10  # Correlation between feeds
        }
        
        # Define confidence thresholds
        self.confidence_thresholds = {
            "high": 0.7,
            "medium": 0.4,
            "low": 0.0
        }
        
        # Cache for API responses to reduce redundant calls
        self.cache = {}
    
    async def correlate_iocs(self, iocs: List[str]) -> Dict:
        """
        Cross-reference IOCs across multiple threat intelligence feeds.
        
        Args:
            iocs: List of IOCs to correlate (domains/URLs/IPs)
            
        Returns:
            Dict containing correlation results and confidence scores
        """
        results = {
            "ioc_correlations": [],
            "summary": {
                "total_iocs": len(iocs),
                "correlated_iocs": 0,
                "high_confidence_count": 0,
                "medium_confidence_count": 0,
                "low_confidence_count": 0,
                "feed_statistics": {}
            },
            "feed_data": {}
        }
        
        # Initialize feed statistics
        feed_stats = {feed: {"ioc_count": 0, "positive_hits": 0} for feed in self.feed_weights.keys()}
        
        # Process each IOC
        for ioc in iocs:
            ioc_result = {
                "ioc": ioc,
                "feeds": {},
                "confidence_score": 0.0,
                "confidence_level": "none",
                "threat_categories": [],
                "first_seen": None,
                "last_seen": None
            }
            
            # Query each threat feed
            virustotal_data = await self._query_virustotal(ioc)
            alienvault_data = await self._query_alienvault_otx(ioc)
            urlhaus_data = await self._query_urlhaus(ioc)
            
            # Process VirusTotal results
            if virustotal_data and not virustotal_data.get("error"):
                ioc_result["feeds"]["virustotal"] = virustotal_data
                feed_stats["virustotal"]["ioc_count"] += 1
                if virustotal_data.get("malicious"):
                    feed_stats["virustotal"]["positive_hits"] += 1
                    ioc_result["threat_categories"].extend(virustotal_data.get("categories", []))
                    if virustotal_data.get("first_submission_date"):
                        ioc_result["first_seen"] = virustotal_data["first_submission_date"]
                    if virustotal_data.get("last_submission_date"):
                        ioc_result["last_seen"] = virustotal_data["last_submission_date"]
            
            # Process AlienVault OTX results
            if alienvault_data and not alienvault_data.get("error"):
                ioc_result["feeds"]["alienvault_otx"] = alienvault_data
                feed_stats["alienvault_otx"]["ioc_count"] += 1
                if alienvault_data.get("malicious"):
                    feed_stats["alienvault_otx"]["positive_hits"] += 1
                    ioc_result["threat_categories"].extend(alienvault_data.get("pulse_names", []))
                    # Update first/last seen if not already set or if this data is earlier/later
                    if alienvault_data.get("first_seen") and (
                            not ioc_result["first_seen"] or 
                            alienvault_data["first_seen"] < ioc_result["first_seen"]):
                        ioc_result["first_seen"] = alienvault_data["first_seen"]
                    if alienvault_data.get("last_seen") and (
                            not ioc_result["last_seen"] or 
                            alienvault_data["last_seen"] > ioc_result["last_seen"]):
                        ioc_result["last_seen"] = alienvault_data["last_seen"]
            
            # Process URLHaus results
            if urlhaus_data and not urlhaus_data.get("error"):
                ioc_result["feeds"]["urlhaus"] = urlhaus_data
                feed_stats["urlhaus"]["ioc_count"] += 1
                if urlhaus_data.get("malicious"):
                    feed_stats["urlhaus"]["positive_hits"] += 1
                    ioc_result["threat_categories"].append("phishing")
                    if urlhaus_data.get("firstseen"):
                        ioc_result["first_seen"] = urlhaus_data["firstseen"]
            
            # Calculate confidence score based on feed consensus
            confidence_score = self._calculate_confidence_score(ioc_result["feeds"])
            ioc_result["confidence_score"] = round(confidence_score, 3)
            ioc_result["confidence_level"] = self._determine_confidence_level(confidence_score)
            
            # Deduplicate threat categories
            ioc_result["threat_categories"] = list(set(ioc_result["threat_categories"]))
            
            results["ioc_correlations"].append(ioc_result)
            
            # Update summary counts
            if confidence_score > 0:
                results["summary"]["correlated_iocs"] += 1
            
            if ioc_result["confidence_level"] == "high":
                results["summary"]["high_confidence_count"] += 1
            elif ioc_result["confidence_level"] == "medium":
                results["summary"]["medium_confidence_count"] += 1
            elif ioc_result["confidence_level"] == "low":
                results["summary"]["low_confidence_count"] += 1
        
        # Add feed statistics to results
        results["summary"]["feed_statistics"] = feed_stats
        results["feed_data"] = {
            "virustotal": {"weight": self.feed_weights["virustotal"]},
            "alienvault_otx": {"weight": self.feed_weights["alienvault_otx"]},
            "urlhaus": {"weight": self.feed_weights["urlhaus"]}
        }
        
        return results
    
    async def _query_virustotal(self, ioc: str) -> Optional[Dict]:
        """Query VirusTotal for IOC information"""
        if not self.virustotal_api_key:
            return {"error": "VirusTotal API key not configured"}
        
        # Check cache first
        cache_key = f"vt_{ioc}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            headers = {
                "x-apikey": self.virustotal_api_key,
                "Accept": "application/json"
            }
            
            # Determine if IOC is a domain, URL, or IP to use appropriate endpoint
            if self._is_domain(ioc):
                url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            elif self._is_ip(ioc):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            else:
                # Assume it's a URL
                import base64
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=15.0)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    
                    # Extract relevant information
                    result = {
                        "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0,
                        "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0) > 0,
                        "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0) > 0,
                        "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                        "categories": list(attributes.get("categories", {}).values()),
                        "first_submission_date": attributes.get("first_submission_date"),
                        "last_submission_date": attributes.get("last_submission_date"),
                        "reputation": attributes.get("reputation", 0),
                        "total_votes": attributes.get("total_votes", {})
                    }
                    
                    # Cache the result
                    self.cache[cache_key] = result
                    return result
                else:
                    return {"error": f"VirusTotal API error: {response.status_code}"}
        except Exception as e:
            return {"error": f"VirusTotal query failed: {str(e)}"}
    
    async def _query_alienvault_otx(self, ioc: str) -> Optional[Dict]:
        """Query AlienVault OTX for IOC information"""
        if not self.alienvault_api_key:
            return {"error": "AlienVault OTX API key not configured"}
        
        # Check cache first
        cache_key = f"otx_{ioc}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            headers = {
                "X-OTX-API-KEY": self.alienvault_api_key,
                "Accept": "application/json"
            }
            
            # Determine if IOC is a domain, URL, or IP to use appropriate endpoint
            if self._is_domain(ioc):
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
            elif self._is_ip(ioc):
                url = f"https://otx.alienvault.com/api/v1/indicators/ip/{ioc}/general"
            else:
                # For URLs, hash and use URL endpoint
                import hashlib
                url_hash = hashlib.sha256(ioc.encode()).hexdigest()
                url = f"https://otx.alienvault.com/api/v1/indicators/url/{url_hash}/general"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=15.0)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract pulse information
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    pulse_names = [pulse.get("name", "") for pulse in pulses]
                    
                    # Extract validation information
                    validation = data.get("validation", [])
                    
                    result = {
                        "malicious": len(pulses) > 0 or len(validation) > 0,
                        "pulse_count": len(pulses),
                        "pulse_names": pulse_names,
                        "first_seen": data.get("pulse_info", {}).get("first_seen"),
                        "last_seen": data.get("pulse_info", {}).get("last_seen"),
                        "sections": list(data.keys())  # Available data sections
                    }
                    
                    # Cache the result
                    self.cache[cache_key] = result
                    return result
                elif response.status_code == 404:
                    # Not found is not an error, just no data
                    result = {
                        "malicious": False,
                        "pulse_count": 0,
                        "pulse_names": [],
                        "sections": []
                    }
                    self.cache[cache_key] = result
                    return result
                else:
                    return {"error": f"AlienVault OTX API error: {response.status_code}"}
        except Exception as e:
            return {"error": f"AlienVault OTX query failed: {str(e)}"}
    
    async def _query_urlhaus(self, ioc: str) -> Optional[Dict]:
        """Query URLHaus for IOC information"""
        # Check cache first
        cache_key = f"urlhaus_{ioc}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            # URLHaus has different endpoints for different types of queries
            if self._is_domain(ioc):
                url = "https://urlhaus-api.abuse.ch/v1/host/"
                payload = {"host": ioc}
            elif self._is_ip(ioc):
                url = "https://urlhaus-api.abuse.ch/v1/host/"
                payload = {"host": ioc}
            else:
                # For URLs
                url = "https://urlhaus-api.abuse.ch/v1/url/"
                payload = {"url": ioc}
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, data=payload, timeout=15.0)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("query_status") == "no_results":
                        result = {
                            "malicious": False,
                            "url_count": 0
                        }
                    else:
                        result = {
                            "malicious": data.get("query_status") == "ok",
                            "url_count": data.get("url_count", 0),
                            "firstseen": data.get("firstseen"),
                            "lastseen": data.get("lastseen", data.get("firstseen")),
                            "urls": data.get("urls", [])
                        }
                    
                    # Cache the result
                    self.cache[cache_key] = result
                    return result
                else:
                    return {"error": f"URLHaus API error: {response.status_code}"}
        except Exception as e:
            return {"error": f"URLHaus query failed: {str(e)}"}
    
    def _calculate_confidence_score(self, feed_data: Dict) -> float:
        """
        Calculate confidence score based on feed consensus.
        
        Args:
            feed_data: Dictionary containing results from different feeds
            
        Returns:
            Float between 0.0 and 1.0 representing confidence score
        """
        if not feed_data:
            return 0.0
        
        score = 0.0
        positive_feeds = 0
        total_feeds = len(feed_data)
        
        # Calculate score based on positive hits and feed weights
        for feed_name, data in feed_data.items():
            if data.get("malicious", False) or data.get("pulse_count", 0) > 0 or data.get("url_count", 0) > 0:
                positive_feeds += 1
                weight = self.feed_weights.get(feed_name, 0)
                score += weight
        
        # Add bonus for consensus (multiple feeds agreeing)
        if positive_feeds > 1:
            consensus_bonus = (positive_feeds / total_feeds) * self.feed_weights.get("internal_correlation", 0.1)
            score += consensus_bonus
        
        # Cap score at 1.0
        return min(1.0, score)
    
    def _determine_confidence_level(self, confidence_score: float) -> str:
        """
        Determine confidence level based on score.
        
        Args:
            confidence_score: Float between 0.0 and 1.0
            
        Returns:
            String representing confidence level ("high", "medium", "low", or "none")
        """
        if confidence_score >= self.confidence_thresholds["high"]:
            return "high"
        elif confidence_score >= self.confidence_thresholds["medium"]:
            return "medium"
        elif confidence_score > self.confidence_thresholds["low"]:
            return "low"
        else:
            return "none"
    
    def _is_domain(self, ioc: str) -> bool:
        """Check if IOC is a domain"""
        import re
        domain_pattern = re.compile(
            r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        )
        return bool(domain_pattern.match(ioc.lower().strip()))
    
    def _is_ip(self, ioc: str) -> bool:
        """Check if IOC is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(ioc)
            return True
        except ValueError:
            return False


# Convenience functions for easier integration
async def correlate_iocs_with_threat_feeds(iocs: List[str]) -> Dict:
    """
    Convenience function to correlate IOCs with threat feeds.
    
    Args:
        iocs: List of IOCs to correlate
        
    Returns:
        Dict containing correlation results
    """
    engine = IOCCorrelationEngine()
    return await engine.correlate_iocs(iocs)


def analyze_correlation_results(correlation_data: Dict) -> Dict:
    """
    Analyze correlation results to identify patterns and trends.
    
    Args:
        correlation_data: Results from IOC correlation
        
    Returns:
        Dict containing analysis results
    """
    analysis = {
        "threat_patterns": [],
        "trending_iocs": [],
        "feed_coverage": {},
        "confidence_distribution": {
            "high": correlation_data["summary"]["high_confidence_count"],
            "medium": correlation_data["summary"]["medium_confidence_count"],
            "low": correlation_data["summary"]["low_confidence_count"],
            "none": correlation_data["summary"]["total_iocs"] - (
                correlation_data["summary"]["high_confidence_count"] +
                correlation_data["summary"]["medium_confidence_count"] +
                correlation_data["summary"]["low_confidence_count"]
            )
        }
    }
    
    # Analyze threat categories
    category_counter = Counter()
    for ioc_result in correlation_data["ioc_correlations"]:
        for category in ioc_result["threat_categories"]:
            category_counter[category] += 1
    
    # Find most common threat categories
    common_categories = category_counter.most_common(10)
    if common_categories:
        analysis["threat_patterns"] = [
            {"category": cat, "count": count} 
            for cat, count in common_categories
        ]
    
    # Identify trending IOCs (those with recent last_seen dates)
    trending = []
    for ioc_result in correlation_data["ioc_correlations"]:
        if ioc_result["last_seen"]:
            trending.append({
                "ioc": ioc_result["ioc"],
                "last_seen": ioc_result["last_seen"],
                "confidence": ioc_result["confidence_level"]
            })
    
    # Sort by last seen date and take top 10
    trending.sort(key=lambda x: x["last_seen"], reverse=True)
    analysis["trending_iocs"] = trending[:10]
    
    # Analyze feed coverage
    for feed, stats in correlation_data["summary"]["feed_statistics"].items():
        analysis["feed_coverage"][feed] = {
            "queried": stats["ioc_count"],
            "positive": stats["positive_hits"],
            "coverage_rate": round(stats["positive_hits"] / max(stats["ioc_count"], 1), 3)
        }
    
    return analysis
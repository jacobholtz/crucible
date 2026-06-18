"""
Infrastructure Timeline Evolution Tracking module for CRUCIBLE SIGINT v5.1
Provides functionality for:
- Tracking how domains move between hosting providers over time
- Creating infrastructure migration pattern databases
- Identifying 'infrastructure hopping' behaviors
"""

import asyncio
import httpx
import json
import re
from typing import List, Dict, Set, Tuple, Optional
from collections import Counter, defaultdict
from datetime import datetime
from asn_intelligence import ASNIntelligence


class InfrastructureTimeline:
    """Infrastructure Timeline tracking and analysis class"""
    
    def __init__(self):
        # Initialize ASN intelligence module
        self.asn_intel = ASNIntelligence()
        
        # Infrastructure migration pattern database
        self.migration_patterns = defaultdict(list)
        
        # Infrastructure hopping indicators
        self.hopping_indicators = {
            "frequent_provider_changes": 0,
            "datacenter_hopping": 0,
            "geo_hopping": 0,
            "short_tenure_ips": 0
        }
        
        # Cache for domain/IP lookups
        self.infra_cache = {}
        
    async def fetch_domain_hosting_history(self, domain: str) -> List[Dict]:
        """
        Fetch historical hosting information for a domain.
        Returns list of hosting events with timestamps, IPs, and providers.
        """
        history = []
        
        # Use multiple sources for comprehensive history
        sources = [
            self._fetch_virustotal_dns_history,
            self._fetch_securitytrails_dns_history,
            self._fetch_crtsh_hosting_history
        ]
        
        # Gather data from all sources concurrently
        results = await asyncio.gather(
            *[source(domain) for source in sources],
            return_exceptions=True
        )
        
        # Consolidate results
        for result in results:
            if isinstance(result, Exception) or not result:
                continue
            if isinstance(result, list):
                history.extend(result)
        
        # Sort by timestamp
        history.sort(key=lambda x: x.get("timestamp", ""))
        return history
    
    async def _fetch_virustotal_dns_history(self, domain: str) -> List[Dict]:
        """Fetch DNS history from VirusTotal (if API key available)."""
        # This would require VT API key - placeholder implementation
        return []
    
    async def _fetch_securitytrails_dns_history(self, domain: str) -> List[Dict]:
        """Fetch DNS history from SecurityTrails (if API key available)."""
        # This would require SecurityTrails API key - placeholder implementation
        return []
    
    async def _fetch_crtsh_hosting_history(self, domain: str) -> List[Dict]:
        """
        Fetch hosting history from crt.sh certificate data.
        Uses certificate issuances as a proxy for infrastructure changes.
        """
        hosting_history = []
        try:
            # Fetch certificate data from crt.sh
            url = f"https://crt.sh/?q={domain}&output=json"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=15.0)
                if response.status_code == 200:
                    certs = response.json()
                    
                    # Extract IP addresses from certificates when available
                    for cert in certs:
                        # This is a simplified approach - real implementation would
                        # extract IP addresses from certificate extensions or logs
                        names = cert.get("name_value", "").split()
                        if domain in names or any(domain in name for name in names):
                            timestamp = cert.get("not_before", "")
                            issuer = cert.get("issuer_name", "")
                            
                            # Add to hosting history
                            hosting_history.append({
                                "timestamp": timestamp,
                                "domain": domain,
                                "source": "cert_transparency",
                                "issuer": issuer,
                                "event_type": "certificate_issuance"
                            })
        except Exception as e:
            pass
            
        return hosting_history
    
    async def track_provider_changes(self, domain: str, ip_history: List[Dict]) -> List[Dict]:
        """
        Track how a domain moves between different hosting providers over time.
        """
        provider_changes = []
        
        if not ip_history:
            return provider_changes
            
        # Get ASN information for each IP in the history
        ips = [entry["ip"] for entry in ip_history if "ip" in entry]
        asn_data_list = await self.asn_intel.bulk_lookup_ips(ips)
        
        # Create a mapping of IP to ASN data for quick lookup
        ip_to_asn = {data["ip"]: data for data in asn_data_list if data}
        
        # Process each IP in chronological order
        prev_provider = None
        prev_timestamp = None
        
        for entry in ip_history:
            ip = entry.get("ip")
            timestamp = entry.get("last_resolved", entry.get("timestamp", ""))
            
            if not ip:
                continue
                
            asn_data = ip_to_asn.get(ip)
            if not asn_data:
                continue
                
            # Determine provider (ASN name or organization)
            provider = (
                asn_data.get("asn_name") or 
                asn_data.get("organization") or 
                asn_data.get("asn_string", f"ASN{asn_data.get('asn', 'Unknown')}")
            )
            
            # Check that we have timestamps for both entries
            if not prev_timestamp or not timestamp:
                prev_provider = provider
                prev_timestamp = timestamp
                entry["prev_ip"] = ip
                continue
            
            # Check if provider changed from previous entry
            if prev_provider and provider != prev_provider:
                provider_changes.append({
                    "domain": domain,
                    "timestamp": timestamp,
                    "from_provider": prev_provider,
                    "to_provider": provider,
                    "from_ip": entry.get("prev_ip", ""),
                    "to_ip": ip,
                    "change_interval_days": self._calculate_days_between(prev_timestamp, timestamp)
                })
                
                # Record this migration pattern
                pattern_key = f"{prev_provider}->{provider}"
                self.migration_patterns[pattern_key].append({
                    "domain": domain,
                    "timestamp": timestamp,
                    "from_ip": entry.get("prev_ip", ""),
                    "to_ip": ip
                })
            
            prev_provider = provider
            prev_timestamp = timestamp
            entry["prev_ip"] = ip  # Store for next iteration
            
        return provider_changes
    
    def _calculate_days_between(self, date1: str, date2: str) -> int:
        """Calculate days between two timestamps."""
        try:
            # Parse ISO format dates
            dt1 = datetime.fromisoformat(date1.replace("Z", "+00:00"))
            dt2 = datetime.fromisoformat(date2.replace("Z", "+00:00"))
            delta = dt2 - dt1
            return delta.days
        except Exception:
            return 0
    
    def identify_hopping_behaviors(self, provider_changes: List[Dict]) -> Dict:
        """
        Identify infrastructure hopping behaviors from provider change data.
        """
        if not provider_changes:
            return {"hopping_score": 0, "indicators": {}, "behavior": "no_movement"}
            
        # Analyze hopping patterns
        hopping_indicators = {
            "frequent_changes": len(provider_changes),
            "short_tenure_changes": 0,
            "distinct_providers": len(set(change["to_provider"] for change in provider_changes)),
            "datacenter_hopping": 0,
            "geo_hopping": 0
        }
        
        # Count changes with short tenure (less than 30 days)
        for change in provider_changes:
            if change.get("change_interval_days", 0) < 30:
                hopping_indicators["short_tenure_changes"] += 1
                
        # Count datacenter hopping (changes between known datacenter providers)
        for change in provider_changes:
            # In real implementation, we would check against datacenter ASNs
            if "datacenter" in change["to_provider"].lower() or "host" in change["to_provider"].lower():
                hopping_indicators["datacenter_hopping"] += 1
                
        # Calculate hopping score (0-100)
        total_changes = len(provider_changes)
        distinct_providers = hopping_indicators["distinct_providers"]
        short_tenure = hopping_indicators["short_tenure_changes"]
        
        # Weighted score based on different factors
        score = min(100, (
            (total_changes * 10) +  # Frequent changes
            (distinct_providers * 15) +  # Many different providers
            (short_tenure * 20)  # Short tenure changes
        ))
        
        # Determine behavior pattern
        if total_changes >= 5 and distinct_providers >= 4:
            behavior = "aggressive_hopping"
        elif total_changes >= 3 and short_tenure >= 2:
            behavior = "frequent_rotation"
        elif distinct_providers >= 3:
            behavior = "provider_diversification"
        else:
            behavior = "normal_migration"
            
        return {
            "hopping_score": score,
            "indicators": hopping_indicators,
            "behavior": behavior,
            "change_count": total_changes
        }
    
    def build_migration_pattern_db(self) -> Dict:
        """
        Build a database of common infrastructure migration patterns.
        """
        pattern_stats = {}
        
        for pattern, migrations in self.migration_patterns.items():
            pattern_stats[pattern] = {
                "count": len(migrations),
                "domains": list(set(m["domain"] for m in migrations)),
                "recent_activity": sorted([m["timestamp"] for m in migrations], reverse=True)[:5]
            }
            
        # Sort patterns by frequency
        sorted_patterns = dict(sorted(
            pattern_stats.items(), 
            key=lambda x: x[1]["count"], 
            reverse=True
        ))
        
        return {
            "total_patterns": len(sorted_patterns),
            "patterns": sorted_patterns,
            "most_common": next(iter(sorted_patterns)) if sorted_patterns else None
        }
    
    async def analyze_infrastructure_timeline(self, domain: str, ip_history: List[Dict]) -> Dict:
        """
        Complete analysis of infrastructure timeline evolution.
        """
        # Track provider changes
        provider_changes = await self.track_provider_changes(domain, ip_history)
        
        # Identify hopping behaviors
        hopping_analysis = self.identify_hopping_behaviors(provider_changes)
        
        # Build timeline of infrastructure events
        infrastructure_timeline = []
        for change in provider_changes:
            infrastructure_timeline.append({
                "date": change.get("timestamp", "")[:10],  # Just the date part
                "month": change.get("timestamp", "")[:7],   # Year-month
                "event_type": "provider_change",
                "from_provider": change["from_provider"],
                "to_provider": change["to_provider"],
                "from_ip": change["from_ip"],
                "to_ip": change["to_ip"]
            })
        
        # Build migration pattern database
        migration_db = self.build_migration_pattern_db()
        
        return {
            "domain": domain,
            "infrastructure_timeline": infrastructure_timeline,
            "provider_changes": provider_changes,
            "hopping_analysis": hopping_analysis,
            "migration_patterns": migration_db,
            "total_movements": len(provider_changes)
        }


# Convenience functions for easier integration

async def fetch_infrastructure_timeline(domain: str, ip_history: List[Dict]) -> Dict:
    """Build infrastructure timeline from IP history data."""
    infra_tracker = InfrastructureTimeline()
    return await infra_tracker.analyze_infrastructure_timeline(domain, ip_history)


def identify_infrastructure_hopping(provider_changes: List[Dict]) -> Dict:
    """Identify infrastructure hopping behaviors."""
    infra_tracker = InfrastructureTimeline()
    return infra_tracker.identify_hopping_behaviors(provider_changes)


def get_migration_patterns() -> Dict:
    """Get database of infrastructure migration patterns."""
    infra_tracker = InfrastructureTimeline()
    return infra_tracker.build_migration_pattern_db()
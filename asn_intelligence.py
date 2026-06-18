"""
ASN Intelligence module for CRUCIBLE SIGINT v5.1
Provides functionality for:
- Mapping IP addresses to their ASNs
- Performing bulk ASN lookups
- Identifying telecom/ISP hosting patterns used by threat actors
- Creating ASN reputation scoring based on historical threat data
"""

import asyncio
import httpx
import json
import re
from typing import List, Dict, Set, Tuple, Optional
from collections import Counter, defaultdict


class ASNIntelligence:
    """ASN Intelligence gathering and analysis class"""
    
    def __init__(self):
        # Load known malicious ASNs from various threat intelligence sources
        self.malicious_asns = {
            47583,  # Hostinger (often used in scam operations)
            24940,  # Hetzner (often used in scam operations)
            16276,  # OVH (often used in scam operations)
            51167,  # Contabo (often used in scam operations)
            9009,   # M247 (often used in scam operations)
            20473,  # Vultr (often used in scam operations)
            39572,  # Flokinet (often used in scam operations)
            62240,  # Choopa (often used in scam operations)
            49454,  # Sharktech (often used in scam operations)
            53667,  # PONYNET (often used in scam operations)
        }
        
        # Known datacenter/hosting provider ASNs (expanded from existing DATACENTER_ASNS)
        self.datacenter_asns = {
            # Major cloud providers
            15169, 16509, 14618, 13335, 8075, 20940, 16591, 54113,
            396982, 19527, 36459, 32934, 63949, 14061, 22822,
            # Chinese cloud providers
            4134, 4837, 9808, 4538,
            # VPS/shared hosting used in scam ops
            47583, 24940, 16276, 51167, 9009, 20473, 39572, 62240, 49454, 53667,
            # Additional hosting providers commonly used in malicious activities
            2906, 32590, 36351, 132203, 394835, 395748, 137039, 
            20953, 46606, 40676, 399280, 396356, 54825
        }
        
        # Telecom ASNs that are sometimes used by threat actors
        self.telecom_asns = {
            # Major telecom providers that may be used for malicious purposes
            701,   # Verizon
            209,   # CenturyLink
            3320,  # Deutsche Telekom
            3215,  # Orange
            3356,  # Level 3
            1299,  # Telia
            6453,  # Tata Communications
            5511,  # Orange S.A.
        }
        
        # Cache for ASN lookups to reduce API calls
        self.asn_cache = {}
        
        # ASN reputation scoring database
        self.asn_reputation_db = defaultdict(int)
        
    async def fetch_ip_to_asn(self, ip: str) -> Optional[Dict]:
        """
        Map an IP address to its ASN information.
        Returns dict with ASN number, organization name, and country.
        """
        # Check cache first
        if ip in self.asn_cache:
            return self.asn_cache[ip]
            
        # Try ip-api.com first (free, but with rate limits)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,as,asname,org,country,countryCode",
                    timeout=10.0
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        # Parse ASN from "AS15169 Google LLC" format
                        as_field = data.get("as", "")
                        asn_match = re.match(r'AS(\d+)', as_field)
                        asn_num = int(asn_match.group(1)) if asn_match else None
                        
                        result = {
                            "ip": ip,
                            "asn": asn_num,
                            "asn_string": as_field,
                            "asn_name": data.get("asname", ""),
                            "organization": data.get("org", ""),
                            "country": data.get("country", ""),
                            "country_code": data.get("countryCode", ""),
                            "is_datacenter": asn_num in self.datacenter_asns if asn_num else False,
                            "is_telecom": asn_num in self.telecom_asns if asn_num else False,
                            "is_malicious": asn_num in self.malicious_asns if asn_num else False
                        }
                        
                        # Cache the result
                        self.asn_cache[ip] = result
                        return result
        except Exception as e:
            pass
            
        # Try Team Cymru whois service as fallback
        try:
            async with httpx.AsyncClient() as client:
                # Team Cymru whois service
                response = await client.get(f"https://whois.cymru.com/cgi-bin/whois.cgi?ip={ip}", timeout=10.0)
                if response.status_code == 200:
                    # Parse Team Cymru response
                    lines = response.text.strip().split('\n')
                    if len(lines) >= 2:
                        # Second line contains the data
                        data_line = lines[1].strip()
                        parts = data_line.split('|')
                        if len(parts) >= 5:
                            asn_num = int(parts[0].strip()) if parts[0].strip().isdigit() else None
                            ip_range = parts[1].strip()
                            country = parts[2].strip()
                            registry = parts[3].strip()
                            allocated = parts[4].strip()
                            
                            result = {
                                "ip": ip,
                                "asn": asn_num,
                                "ip_range": ip_range,
                                "country": country,
                                "registry": registry,
                                "allocated": allocated,
                                "is_datacenter": asn_num in self.datacenter_asns if asn_num else False,
                                "is_telecom": asn_num in self.telecom_asns if asn_num else False,
                                "is_malicious": asn_num in self.malicious_asns if asn_num else False
                            }
                            
                            # Cache the result
                            self.asn_cache[ip] = result
                            return result
        except Exception as e:
            pass
            
        return None
    
    async def bulk_lookup_ips(self, ips: List[str]) -> List[Dict]:
        """
        Perform bulk ASN lookups for a list of IP addresses.
        Returns a list of ASN information for each IP.
        """
        results = []
        # Process in batches to avoid rate limiting
        batch_size = 10
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i+batch_size]
            batch_results = await asyncio.gather(
                *[self.fetch_ip_to_asn(ip) for ip in batch],
                return_exceptions=True
            )
            for result in batch_results:
                if isinstance(result, Exception):
                    continue
                if result:
                    results.append(result)
            # Small delay between batches
            if i + batch_size < len(ips):
                await asyncio.sleep(0.5)
        return results
    
    def identify_hosting_patterns(self, asn_data_list: List[Dict]) -> Dict:
        """
        Identify telecom/ISP hosting patterns used by threat actors.
        Analyzes ASN data to detect suspicious patterns.
        """
        if not asn_data_list:
            return {
                "hosting_patterns": [],
                "suspicious_asns": [],
                "datacenter_ips": 0,
                "telecom_ips": 0,
                "malicious_ips": 0
            }
            
        # Count occurrences of each ASN
        asn_counter = Counter()
        datacenter_count = 0
        telecom_count = 0
        malicious_count = 0
        suspicious_asns = []
        
        for data in asn_data_list:
            if data.get("asn"):
                asn_counter[data["asn"]] += 1
                if data.get("is_datacenter"):
                    datacenter_count += 1
                if data.get("is_telecom"):
                    telecom_count += 1
                if data.get("is_malicious"):
                    malicious_count += 1
                    if data["asn"] not in suspicious_asns:
                        suspicious_asns.append(data["asn"])
        
        # Find frequently occurring ASNs that might indicate infrastructure patterns
        hosting_patterns = []
        for asn, count in asn_counter.most_common(10):
            if count > 1:  # Only include ASNs that appear more than once
                hosting_patterns.append({
                    "asn": asn,
                    "count": count,
                    "percentage": round((count / len(asn_data_list)) * 100, 2)
                })
        
        return {
            "hosting_patterns": hosting_patterns,
            "suspicious_asns": suspicious_asns,
            "datacenter_ips": datacenter_count,
            "telecom_ips": telecom_count,
            "malicious_ips": malicious_count
        }
    
    def update_asn_reputation(self, asn: int, threat_score: int):
        """
        Update reputation score for an ASN based on threat intelligence.
        Higher scores indicate more malicious activity.
        """
        self.asn_reputation_db[asn] += threat_score
    
    def get_asn_reputation(self, asn: int) -> int:
        """
        Get reputation score for an ASN.
        Returns 0 for unknown ASNs, positive values for known malicious ASNs.
        """
        return self.asn_reputation_db.get(asn, 0)
    
    def generate_asn_report(self, ips: List[str], ip_asn_mapping: List[Dict]) -> Dict:
        """
        Generate a comprehensive ASN intelligence report.
        """
        # Identify hosting patterns
        patterns = self.identify_hosting_patterns(ip_asn_mapping)
        
        # Count unique ASNs
        unique_asns = set()
        for data in ip_asn_mapping:
            if data.get("asn"):
                unique_asns.add(data["asn"])
        
        # Calculate ASN reputation scores
        asn_reputations = {}
        for asn in unique_asns:
            asn_reputations[asn] = self.get_asn_reputation(asn)
        
        # Identify countries with high ASN concentration
        country_counter = Counter()
        for data in ip_asn_mapping:
            if data.get("country_code"):
                country_counter[data["country_code"]] += 1
        
        top_countries = country_counter.most_common(5)
        
        return {
            "summary": {
                "total_ips": len(ips),
                "unique_asns": len(unique_asns),
                "datacenter_ips": patterns["datacenter_ips"],
                "telecom_ips": patterns["telecom_ips"],
                "malicious_ips": patterns["malicious_ips"],
                "suspicious_asns_count": len(patterns["suspicious_asns"])
            },
            "hosting_patterns": patterns["hosting_patterns"],
            "suspicious_asns": patterns["suspicious_asns"],
            "top_countries": [{"country": code, "count": count, "percentage": round((count/len(ips))*100, 2)} 
                             for code, count in top_countries],
            "asn_reputations": asn_reputations
        }


# Convenience functions for easier integration

async def map_ip_to_asn(ip: str) -> Optional[Dict]:
    """Map a single IP to its ASN information."""
    asn_intel = ASNIntelligence()
    return await asn_intel.fetch_ip_to_asn(ip)

async def bulk_lookup_asns(ips: List[str]) -> List[Dict]:
    """Perform bulk ASN lookups for multiple IPs."""
    asn_intel = ASNIntelligence()
    return await asn_intel.bulk_lookup_ips(ips)

def analyze_hosting_patterns(asn_data_list: List[Dict]) -> Dict:
    """Analyze hosting patterns from ASN data."""
    asn_intel = ASNIntelligence()
    return asn_intel.identify_hosting_patterns(asn_data_list)

def generate_asn_report(ips: List[str], ip_asn_mapping: List[Dict]) -> Dict:
    """Generate a comprehensive ASN intelligence report."""
    asn_intel = ASNIntelligence()
    return asn_intel.generate_asn_report(ips, ip_asn_mapping)
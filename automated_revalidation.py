"""
Automated Revalidation & Change Detection module for CRUCIBLE SIGINT v5.1
Provides functionality for:
- Scheduling recurring checks of discovered infrastructure
- Flagging when domains go offline/change hosting/modify infrastructure
- Creating 'infrastructure decay' scoring for takedown effectiveness
- Generating alerts for reactivated domains
"""

import asyncio
import json
import httpx
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict

from infrastructure_timeline import InfrastructureTimeline


class AutomatedRevalidation:
    """Automated infrastructure revalidation and change detection system"""
    
    def __init__(self, findings_storage_path: str = "findings_storage.json"):
        self.findings_storage_path = findings_storage_path
        self.revalidation_schedule = {}  # domain -> schedule info
        self.infrastructure_timeline = InfrastructureTimeline()
        self.findings_data = self._load_findings_data()
        self.decay_scores = defaultdict(float)  # domain -> decay score
        self.alerts = []  # List of generated alerts
        
    def _load_findings_data(self) -> Dict:
        """Load existing findings data from storage"""
        try:
            if os.path.exists(self.findings_storage_path):
                with open(self.findings_storage_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading findings data: {e}")
        return {}
    
    def _save_findings_data(self):
        """Save findings data to storage"""
        try:
            with open(self.findings_storage_path, 'w') as f:
                json.dump(self.findings_data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving findings data: {e}")
    
    def register_domain_for_revalidation(self, domain: str, frequency_hours: int = 24):
        """Register a domain for automated revalidation checks"""
        self.revalidation_schedule[domain] = {
            "frequency_hours": frequency_hours,
            "last_checked": None,
            "next_check": datetime.now() + timedelta(hours=frequency_hours),
            "status": "active"
        }
        
    def unregister_domain_from_revalidation(self, domain: str):
        """Remove a domain from automated revalidation checks"""
        if domain in self.revalidation_schedule:
            del self.revalidation_schedule[domain]
    
    async def check_domain_status(self, domain: str) -> Dict[str, Any]:
        """
        Check current status of a domain including:
        - DNS resolution status
        - Hosting provider changes
        - SSL certificate changes
        """
        status_info = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "online": False,
            "ip_address": None,
            "hosting_provider": None,
            "ssl_info": None,
            "changes_detected": [],
            "errors": []
        }
        
        try:
            # Check DNS resolution
            ip_address = await self._resolve_domain(domain)
            if ip_address:
                status_info["online"] = True
                status_info["ip_address"] = ip_address
                
                # Get hosting provider info
                asn_info = await self.infrastructure_timeline.asn_intel.fetch_ip_to_asn(ip_address)
                if asn_info:
                    status_info["hosting_provider"] = (
                        asn_info.get("asn_name") or 
                        asn_info.get("organization") or 
                        f"ASN{asn_info.get('asn', 'Unknown')}"
                    )
                
                # Get SSL certificate info
                ssl_info = await self._get_ssl_info(domain)
                status_info["ssl_info"] = ssl_info
            else:
                status_info["online"] = False
        except Exception as e:
            status_info["errors"].append(str(e))
            
        return status_info
    
    async def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    if "Answer" in data:
                        for answer in data["Answer"]:
                            if answer.get("type") == 1:  # A record
                                return answer.get("data")
        except Exception:
            pass
        return None
    
    async def _get_ssl_info(self, domain: str) -> Dict:
        """Get basic SSL certificate information"""
        ssl_info = {"valid": False, "issuer": None, "expiration": None}
        try:
            # In a real implementation, we would fetch actual SSL info
            # For now, we'll just return placeholder data
            ssl_info["valid"] = True  # Assume valid for demo
        except Exception:
            pass
        return ssl_info
    
    def calculate_infrastructure_decay(self, domain: str, previous_status: Dict, current_status: Dict) -> float:
        """
        Calculate infrastructure decay score based on changes.
        Score ranges from 0 (no decay) to 100 (complete decay).
        """
        decay_score = 0.0
        
        # Check if domain went offline
        if previous_status.get("online", False) and not current_status.get("online", False):
            decay_score += 30.0
        
        # Check hosting provider changes
        prev_provider = previous_status.get("hosting_provider")
        curr_provider = current_status.get("hosting_provider")
        if prev_provider and curr_provider and prev_provider != curr_provider:
            decay_score += 25.0
        
        # Check IP address changes
        prev_ip = previous_status.get("ip_address")
        curr_ip = current_status.get("ip_address")
        if prev_ip and curr_ip and prev_ip != curr_ip:
            decay_score += 20.0
        
        # Check SSL certificate changes
        prev_ssl = previous_status.get("ssl_info", {})
        curr_ssl = current_status.get("ssl_info", {})
        if prev_ssl.get("issuer") != curr_ssl.get("issuer"):
            decay_score += 15.0
        
        # Cap at 100
        return min(100.0, decay_score)
    
    def generate_decay_alert(self, domain: str, decay_score: float, changes: List[str]) -> Dict:
        """Generate an alert based on infrastructure decay"""
        severity = "low"
        if decay_score >= 70:
            severity = "critical"
        elif decay_score >= 50:
            severity = "high"
        elif decay_score >= 30:
            severity = "medium"
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "decay_score": decay_score,
            "severity": severity,
            "changes": changes,
            "message": f"Infrastructure decay detected for {domain} (Score: {decay_score})"
        }
        
        self.alerts.append(alert)
        return alert
    
    def check_for_reactivated_domains(self, domain: str, current_status: Dict) -> Optional[Dict]:
        """Check if a previously offline domain is now back online"""
        previous_status = self.findings_data.get(domain, {}).get("last_status", {})

        # If domain was previously recorded as offline and is now online.
        # Use `is False` so a first-ever check (no prior status, .get() -> None)
        # is not mistaken for a reactivation.
        if (previous_status.get("online") is False and
            current_status.get("online", False)):
            alert = {
                "timestamp": datetime.now().isoformat(),
                "domain": domain,
                "type": "reactivated",
                "message": f"Domain {domain} has been reactivated",
                "severity": "high"
            }
            self.alerts.append(alert)
            return alert
        return None
    
    async def perform_revalidation_check(self, domain: str) -> Dict:
        """Perform a single revalidation check for a domain"""
        # Get current status
        current_status = await self.check_domain_status(domain)
        
        # Get previous status
        previous_status = self.findings_data.get(domain, {}).get("last_status", {})
        
        # Detect changes
        changes = []
        if previous_status:
            # Compare with previous status to detect changes
            if previous_status.get("online") != current_status.get("online"):
                changes.append("online_status_change")
                
            if previous_status.get("hosting_provider") != current_status.get("hosting_provider"):
                changes.append("hosting_provider_change")
                
            if previous_status.get("ip_address") != current_status.get("ip_address"):
                changes.append("ip_address_change")
        
        # Calculate decay score
        decay_score = self.calculate_infrastructure_decay(domain, previous_status, current_status)
        self.decay_scores[domain] = decay_score
        
        # Generate alerts for significant changes
        alert = None
        if changes:
            alert = self.generate_decay_alert(domain, decay_score, changes)
        
        # Check for reactivated domains
        reactivation_alert = self.check_for_reactivated_domains(domain, current_status)
        
        # Update findings data
        if domain not in self.findings_data:
            self.findings_data[domain] = {}
            
        self.findings_data[domain]["last_status"] = current_status
        self.findings_data[domain]["last_checked"] = datetime.now().isoformat()
        self.findings_data[domain]["decay_score"] = decay_score
        self.findings_data[domain]["changes"] = changes
        
        # Save updated findings
        self._save_findings_data()
        
        return {
            "domain": domain,
            "current_status": current_status,
            "decay_score": decay_score,
            "changes": changes,
            "alert": alert,
            "reactivation_alert": reactivation_alert
        }
    
    async def run_scheduled_revalidations(self):
        """Run scheduled revalidation checks for all registered domains"""
        results = []
        now = datetime.now()
        
        for domain, schedule_info in self.revalidation_schedule.items():
            if schedule_info["status"] == "active":
                next_check = schedule_info["next_check"]
                if now >= next_check:
                    # Perform revalidation check
                    result = await self.perform_revalidation_check(domain)
                    results.append(result)
                    
                    # Update next check time
                    frequency_hours = schedule_info["frequency_hours"]
                    schedule_info["next_check"] = now + timedelta(hours=frequency_hours)
                    schedule_info["last_checked"] = now.isoformat()
        
        return results
    
    def get_decay_report(self) -> Dict:
        """Generate a report of infrastructure decay scores"""
        sorted_decay = sorted(self.decay_scores.items(), key=lambda x: x[1], reverse=True)
        return {
            "timestamp": datetime.now().isoformat(),
            "decay_scores": dict(sorted_decay),
            "total_domains": len(self.decay_scores),
            "high_decay_domains": [domain for domain, score in sorted_decay if score >= 50],
            "medium_decay_domains": [domain for domain, score in sorted_decay if 30 <= score < 50],
            "low_decay_domains": [domain for domain, score in sorted_decay if score < 30]
        }
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_alerts = []
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
            if alert_time >= cutoff_time:
                recent_alerts.append(alert)
                
        return recent_alerts


# Convenience functions for easier integration

def create_automated_revalidation_system(findings_storage_path: str = "findings_storage.json") -> AutomatedRevalidation:
    """Create an automated revalidation system instance"""
    return AutomatedRevalidation(findings_storage_path)


async def register_domain_for_monitoring(revalidation_system: AutomatedRevalidation, domain: str, frequency_hours: int = 24):
    """Register a domain for automated monitoring"""
    revalidation_system.register_domain_for_revalidation(domain, frequency_hours)


async def run_domain_revalidation(revalidation_system: AutomatedRevalidation, domain: str) -> Dict:
    """Run a revalidation check for a specific domain"""
    return await revalidation_system.perform_revalidation_check(domain)


async def run_scheduled_revalidations(revalidation_system: AutomatedRevalidation) -> List[Dict]:
    """Run all scheduled revalidation checks"""
    return await revalidation_system.run_scheduled_revalidations()


def get_infrastructure_decay_report(revalidation_system: AutomatedRevalidation) -> Dict:
    """Get infrastructure decay report"""
    return revalidation_system.get_decay_report()


def get_recent_alerts(revalidation_system: AutomatedRevalidation, hours: int = 24) -> List[Dict]:
    """Get recent alerts"""
    return revalidation_system.get_recent_alerts(hours)
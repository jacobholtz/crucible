"""
Test script for Automated Revalidation & Change Detection feature
"""

import asyncio
import json
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from automated_revalidation import AutomatedRevalidation


async def test_automated_revalidation():
    """Test the automated revalidation system"""
    print("Testing Automated Revalidation System...")
    
    # Create revalidation system
    revalidation_system = AutomatedRevalidation("test_findings.json")
    
    # Register a test domain
    test_domain = "example.com"
    revalidation_system.register_domain_for_revalidation(test_domain, frequency_hours=1)
    print(f"Registered {test_domain} for revalidation")
    
    # Check domain status
    print("Checking domain status...")
    status = await revalidation_system.check_domain_status(test_domain)
    print(f"Status: {json.dumps(status, indent=2)}")
    
    # Perform revalidation check
    print("Performing revalidation check...")
    result = await revalidation_system.perform_revalidation_check(test_domain)
    print(f"Revalidation result: {json.dumps(result, indent=2)}")
    
    # Get decay report
    report = revalidation_system.get_decay_report()
    print(f"Decay report: {json.dumps(report, indent=2)}")
    
    # Get recent alerts
    alerts = revalidation_system.get_recent_alerts()
    print(f"Recent alerts: {json.dumps(alerts, indent=2)}")
    
    print("Test completed successfully!")


if __name__ == "__main__":
    asyncio.run(test_automated_revalidation())
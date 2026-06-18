#!/usr/bin/env python3
"""
Test script for Infrastructure Timeline Evolution Tracking feature
"""

import asyncio
import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from infrastructure_timeline import InfrastructureTimeline

async def test_infrastructure_timeline():
    """Test the infrastructure timeline functionality"""
    print("Testing Infrastructure Timeline Evolution Tracking...")
    
    # Create an instance of the infrastructure timeline tracker
    infra_tracker = InfrastructureTimeline()
    
    # Test data - simulated IP history for a domain
    test_ip_history = [
        {
            "ip": "192.168.1.1",
            "last_resolved": "2026-01-01T10:00:00Z",
        },
        {
            "ip": "192.168.1.2",
            "last_resolved": "2026-02-01T10:00:00Z",
        },
        {
            "ip": "192.168.1.3",
            "last_resolved": "2026-03-01T10:00:00Z",
        }
    ]
    
    # Test the infrastructure timeline analysis
    result = await infra_tracker.analyze_infrastructure_timeline("testdomain.com", test_ip_history)
    
    print("Infrastructure Timeline Analysis Result:")
    print(f"Domain: {result['domain']}")
    print(f"Total Movements: {result['total_movements']}")
    print(f"Hopping Score: {result['hopping_analysis']['hopping_score']}")
    print(f"Behavior: {result['hopping_analysis']['behavior']}")
    
    # Test the migration pattern database
    patterns = infra_tracker.build_migration_pattern_db()
    print(f"Migration Patterns: {patterns['total_patterns']} patterns found")
    
    return result

if __name__ == "__main__":
    asyncio.run(test_infrastructure_timeline())
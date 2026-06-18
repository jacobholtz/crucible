#!/usr/bin/env python3
"""
Verification script for Infrastructure Timeline Evolution Tracking feature
"""

import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def verify_modules():
    """Verify that all required modules can be imported"""
    try:
        from infrastructure_timeline import InfrastructureTimeline
        print("✓ infrastructure_timeline module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import infrastructure_timeline: {e}")
        return False
    
    try:
        from crucible_app import fetch_cert_timeline
        print("✓ crucible_app module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import crucible_app: {e}")
        return False
        
    try:
        from asn_intelligence import ASNIntelligence
        print("✓ asn_intelligence module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import asn_intelligence: {e}")
        return False
        
    return True

def verify_files():
    """Verify that all required files exist"""
    required_files = [
        "infrastructure_timeline.py",
        "crucible_app.py",
        "asn_intelligence.py",
        "ENHANCEMENTS_SUMMARY.md",
        "INFRASTRUCTURE_TIMELINE.md"
    ]
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ {file} exists")
        else:
            print(f"✗ {file} missing")
            return False
            
    return True

def main():
    """Main verification function"""
    print("Verifying Infrastructure Timeline Evolution Tracking Implementation...")
    print()
    
    if not verify_files():
        print("File verification failed!")
        return 1
        
    if not verify_modules():
        print("Module verification failed!")
        return 1
        
    print()
    print("✓ All verifications passed! Implementation is ready.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
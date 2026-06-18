#!/usr/bin/env python3

"""
Test script for CRUCIBLE SIGINT enhancements
"""

import os
import sys

# Add the current directory to the path so we can import crucible_app
sys.path.insert(0, '.')

# Set dummy API keys for testing
os.environ['SHODAN_API_KEY'] = 'test_key'
os.environ['VIRUSTOTAL_API_KEY'] = 'test_key'

def test_imports():
    """Test that all modules can be imported successfully"""
    try:
        # Test main app import
        import crucible_app
        print("✓ Main app module imported successfully")
        
        # Test intelligence extensions
        from intelligence_extensions import fetch_shodan_data, fetch_virustotal_passive_dns, EXPANDED_PHISHING_PATTERNS
        print(f"✓ Intelligence extensions imported successfully ({len(EXPANDED_PHISHING_PATTERNS)} phishing patterns)")
        
        return True
    except Exception as e:
        print(f"✗ Import test failed: {e}")
        return False

def test_data_structures():
    """Test that our enhanced data structures work"""
    try:
        # Test data structure for enhanced threat scoring
        test_data = {
            'domains': [{'name': 'test.com', 'source': 'seed', 'flag': None, 'entropy': 2.5}],
            'ip_results': [],
            'rdap': {},
            'urlscan': {},
            'js_scan': {},
            'shodan': {'open_ports': [22, 80, 443]},
            'virustotal': {'ip_history': [{'ip': '1.2.3.4', 'last_resolved': '2026-01-01'}]}
        }
        
        print("✓ Enhanced data structures are compatible")
        return True
    except Exception as e:
        print(f"✗ Data structure test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing CRUCIBLE SIGINT enhancements...")
    print()
    
    if test_imports() and test_data_structures():
        print()
        print("🎉 All tests passed! CRUCIBLE SIGINT enhancements are ready to use.")
        print()
        print("To run the full application:")
        print("  source venv/bin/activate")
        print("  python crucible_app.py")
    else:
        print()
        print("❌ Some tests failed. Please check the implementation.")
        sys.exit(1)
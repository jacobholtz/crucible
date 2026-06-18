"""
Unit tests for Automated Revalidation & Change Detection feature
"""

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch, AsyncMock

from automated_revalidation import AutomatedRevalidation


class TestAutomatedRevalidation(unittest.TestCase):
    """Test cases for AutomatedRevalidation class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a temporary file for test findings
        self.test_findings_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.test_findings_file.close()
        
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove the temporary file
        if os.path.exists(self.test_findings_file.name):
            os.unlink(self.test_findings_file.name)
    
    def test_init(self):
        """Test initialization of AutomatedRevalidation"""
        revalidation_system = AutomatedRevalidation(self.test_findings_file.name)
        self.assertIsInstance(revalidation_system, AutomatedRevalidation)
        self.assertEqual(revalidation_system.findings_storage_path, self.test_findings_file.name)
        self.assertEqual(len(revalidation_system.revalidation_schedule), 0)
        self.assertEqual(len(revalidation_system.decay_scores), 0)
        
    def test_register_domain_for_revalidation(self):
        """Test registering a domain for revalidation"""
        revalidation_system = AutomatedRevalidation(self.test_findings_file.name)
        test_domain = "example.com"
        
        revalidation_system.register_domain_for_revalidation(test_domain, frequency_hours=12)
        
        self.assertIn(test_domain, revalidation_system.revalidation_schedule)
        schedule_info = revalidation_system.revalidation_schedule[test_domain]
        self.assertEqual(schedule_info["frequency_hours"], 12)
        self.assertEqual(schedule_info["status"], "active")
        
    def test_unregister_domain_from_revalidation(self):
        """Test unregistering a domain from revalidation"""
        revalidation_system = AutomatedRevalidation(self.test_findings_file.name)
        test_domain = "example.com"
        
        # First register the domain
        revalidation_system.register_domain_for_revalidation(test_domain)
        self.assertIn(test_domain, revalidation_system.revalidation_schedule)
        
        # Then unregister it
        revalidation_system.unregister_domain_from_revalidation(test_domain)
        self.assertNotIn(test_domain, revalidation_system.revalidation_schedule)
        
    def test_calculate_infrastructure_decay(self):
        """Test infrastructure decay calculation"""
        revalidation_system = AutomatedRevalidation(self.test_findings_file.name)
        test_domain = "example.com"
        
        # Test case 1: Domain goes offline
        previous_status = {"online": True, "hosting_provider": "ProviderA", "ip_address": "1.2.3.4"}
        current_status = {"online": False, "hosting_provider": "ProviderA", "ip_address": "1.2.3.4"}
        decay_score = revalidation_system.calculate_infrastructure_decay(test_domain, previous_status, current_status)
        self.assertEqual(decay_score, 30.0)
        
        # Test case 2: Hosting provider changes
        previous_status = {"online": True, "hosting_provider": "ProviderA", "ip_address": "1.2.3.4"}
        current_status = {"online": True, "hosting_provider": "ProviderB", "ip_address": "1.2.3.4"}
        decay_score = revalidation_system.calculate_infrastructure_decay(test_domain, previous_status, current_status)
        self.assertEqual(decay_score, 25.0)
        
        # Test case 3: Multiple changes
        previous_status = {"online": True, "hosting_provider": "ProviderA", "ip_address": "1.2.3.4"}
        current_status = {"online": False, "hosting_provider": "ProviderB", "ip_address": "5.6.7.8"}
        decay_score = revalidation_system.calculate_infrastructure_decay(test_domain, previous_status, current_status)
        self.assertEqual(decay_score, 75.0)  # 30 for offline + 25 for provider change + 20 for IP change
        
    def test_generate_decay_alert(self):
        """Test decay alert generation"""
        revalidation_system = AutomatedRevalidation(self.test_findings_file.name)
        test_domain = "example.com"
        
        # Generate a high decay alert
        changes = ["online_status_change", "hosting_provider_change"]
        alert = revalidation_system.generate_decay_alert(test_domain, 60.0, changes)
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert["domain"], test_domain)
        self.assertEqual(alert["decay_score"], 60.0)
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["changes"], changes)
        
        # Check that alert was added to alerts list
        self.assertIn(alert, revalidation_system.alerts)
        
    def test_get_decay_report(self):
        """Test decay report generation"""
        revalidation_system = AutomatedRevalidation(self.test_findings_file.name)
        
        # Add some test decay scores
        revalidation_system.decay_scores["domain1.com"] = 75.0
        revalidation_system.decay_scores["domain2.com"] = 45.0
        revalidation_system.decay_scores["domain3.com"] = 15.0
        
        report = revalidation_system.get_decay_report()
        
        self.assertIn("timestamp", report)
        self.assertEqual(report["total_domains"], 3)
        self.assertIn("domain1.com", report["decay_scores"])
        self.assertIn("domain1.com", report["high_decay_domains"])
        self.assertIn("domain2.com", report["medium_decay_domains"])
        self.assertIn("domain3.com", report["low_decay_domains"])


if __name__ == "__main__":
    unittest.main()
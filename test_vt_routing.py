"""Tests for the VirusTotal passive-DNS routing fix.

Covers:
 - Domain seed → /domains/{d}/resolutions, response shaped as `ip_history`.
 - IP seed → /ip_addresses/{ip}/resolutions, response shaped as `domain_history`.
 - IOC-correlation engine still routes IPs to ip_addresses endpoint.
 - The "virustault" → "virustotal" feed-stats typo no longer raises KeyError.
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from intelligence_extensions import (
    fetch_virustotal_passive_dns,
    fetch_virustotal_reputation,
)
from ioc_correlation_engine import IOCCorrelationEngine


def _resp(json_payload, status=200):
    m = MagicMock()
    m.status_code = status
    m.json = MagicMock(return_value=json_payload)
    return m


class FetchVirusTotalPassiveDnsTests(unittest.TestCase):
    def test_domain_seed_hits_domains_endpoint(self):
        payload = {"data": [
            {"id": "1.2.3.4example.com",
             "attributes": {"ip_address": "1.2.3.4", "date": 1700000000}}
        ]}
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp(payload))
            out = asyncio.run(fetch_virustotal_passive_dns("example.com", "k"))
            url = client.get.call_args[0][0]
            self.assertIn("/domains/example.com/resolutions", url)
            self.assertNotIn("/ip_addresses/", url)
        self.assertEqual(out["domain"], "example.com")
        self.assertEqual(out["ip_history"][0]["ip"], "1.2.3.4")
        self.assertNotIn("domain_history", out)

    def test_ip_seed_hits_ip_addresses_endpoint(self):
        payload = {"data": [
            {"id": "1.2.3.4example.com",
             "attributes": {"host_name": "example.com", "date": 1700000000}}
        ]}
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp(payload))
            out = asyncio.run(fetch_virustotal_passive_dns("1.2.3.4", "k"))
            url = client.get.call_args[0][0]
            self.assertIn("/ip_addresses/1.2.3.4/resolutions", url)
            self.assertNotIn("/domains/", url)
        self.assertEqual(out["ip"], "1.2.3.4")
        self.assertEqual(out["domain_history"][0]["domain"], "example.com")
        self.assertNotIn("ip_history", out)

    def test_ipv6_seed_hits_ip_addresses_endpoint(self):
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp({"data": []}))
            asyncio.run(fetch_virustotal_passive_dns("2001:db8::1", "k"))
            url = client.get.call_args[0][0]
            self.assertIn("/ip_addresses/2001:db8::1/resolutions", url)

    def test_missing_api_key_short_circuits(self):
        out = asyncio.run(fetch_virustotal_passive_dns("1.2.3.4", ""))
        self.assertIn("error", out)

    def test_api_error_propagates(self):
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp({}, status=503))
            out = asyncio.run(fetch_virustotal_passive_dns("1.2.3.4", "k"))
        self.assertIn("error", out)
        self.assertIn("503", out["error"])


class FetchVirusTotalReputationTests(unittest.TestCase):
    def test_domain_seed_hits_domains_endpoint(self):
        payload = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                    "harmless": 70, "undetected": 20, "timeout": 0},
            "reputation": 5,
        }}}
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp(payload))
            out = asyncio.run(fetch_virustotal_reputation("example.com", "k"))
            url = client.get.call_args[0][0]
            self.assertIn("/domains/example.com", url)
            self.assertNotIn("/ip_addresses/", url)
        self.assertEqual(out["domain"], "example.com")
        self.assertEqual(out["verdict"], "clean")
        self.assertIn("/gui/domain/", out["permalink"])

    def test_ip_seed_hits_ip_addresses_endpoint(self):
        # Reproduces the prior 400 — IP seeds now route to the IP endpoint.
        payload = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1,
                                    "harmless": 60, "undetected": 30, "timeout": 0},
            "reputation": -5,
        }}}
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp(payload))
            out = asyncio.run(fetch_virustotal_reputation("195.201.194.107", "k"))
            url = client.get.call_args[0][0]
            self.assertIn("/ip_addresses/195.201.194.107", url)
            self.assertNotIn("/domains/", url)
        self.assertEqual(out["ip"], "195.201.194.107")
        self.assertEqual(out["verdict"], "malicious")
        self.assertIn("/gui/ip-address/", out["permalink"])

    def test_404_returns_unknown_for_ip_seed(self):
        with patch("intelligence_extensions.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp({}, status=404))
            out = asyncio.run(fetch_virustotal_reputation("1.2.3.4", "k"))
        self.assertTrue(out.get("not_found"))
        self.assertEqual(out["verdict"], "unknown")
        self.assertEqual(out["ip"], "1.2.3.4")


class IocEngineRoutingTests(unittest.TestCase):
    def setUp(self):
        self.engine = IOCCorrelationEngine()
        self.engine.virustotal_api_key = "k"

    def test_is_domain_rejects_ipv4(self):
        self.assertFalse(self.engine._is_domain("192.168.1.1"))
        self.assertFalse(self.engine._is_domain("10.0.0.10"))

    def test_is_domain_accepts_domains(self):
        self.assertTrue(self.engine._is_domain("example.com"))
        self.assertTrue(self.engine._is_domain("sub.example.co.uk"))

    def test_is_ip_accepts_ipv4_and_ipv6(self):
        self.assertTrue(self.engine._is_ip("192.168.1.1"))
        self.assertTrue(self.engine._is_ip("2001:db8::1"))

    def test_vt_query_routes_ip_to_ip_addresses(self):
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
        with patch("ioc_correlation_engine.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp(payload))
            asyncio.run(self.engine._query_virustotal("8.8.8.8"))
            url = client.get.call_args[0][0]
            self.assertIn("/ip_addresses/8.8.8.8", url)

    def test_vt_query_routes_domain_to_domains(self):
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
        with patch("ioc_correlation_engine.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(return_value=_resp(payload))
            asyncio.run(self.engine._query_virustotal("example.com"))
            url = client.get.call_args[0][0]
            self.assertIn("/domains/example.com", url)

    def test_feed_stats_typo_fixed_for_malicious_vt_hit(self):
        # Before the fix this would raise KeyError on "virustault".
        vt_payload = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 1},
            "categories": {"x": "malware"},
            "first_submission_date": 1,
            "last_submission_date": 2,
        }}}
        empty = {"data": {"attributes": {}}}
        with patch("ioc_correlation_engine.httpx.AsyncClient") as Client:
            client = Client.return_value.__aenter__.return_value
            client.get = AsyncMock(side_effect=[
                _resp(vt_payload),       # VT
                _resp(empty, status=404), # OTX → handled
                _resp({"query_status": "no_results"}),  # URLHaus
            ])
            client.post = AsyncMock(return_value=_resp({"query_status": "no_results"}))
            self.engine.alienvault_api_key = "k"
            results = asyncio.run(self.engine.correlate_iocs(["example.com"]))
        stats = results["summary"]["feed_statistics"]
        self.assertEqual(stats["virustotal"]["positive_hits"], 1)


if __name__ == "__main__":
    unittest.main()

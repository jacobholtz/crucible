# CRUCIBLE SIGINT v5.1 - Enhanced Infrastructure Pivoting Capabilities

## Overview
CRUCIBLE SIGINT v5.1 introduces 10 new automated infrastructure pivoting capabilities that significantly expand the tool's threat intelligence capabilities beyond the original 7-stage pipeline. These enhancements provide deeper insights into malicious infrastructure patterns and enable more comprehensive threat actor attribution.

## New Features

### 1. Reverse IP Lookup Expansion (Stage 13)
- Performs reverse IP lookups to discover ALL domains hosted on the same infrastructure
- Correlates IP neighbors to map hosting provider networks
- Identifies shared infrastructure patterns across different scam operations
- Adds Signal S15 to threat scoring model (weight: 2.0)

### 2. ASN Intelligence Gathering (Stage 4)
- Maps IP addresses to their ASNs with detailed information
- Performs bulk ASN lookups for efficiency
- Identifies telecom/ISP hosting patterns used by threat actors
- Creates ASN reputation scoring based on historical threat data
- Adds comprehensive ASN intelligence reporting

### 3. SSL Certificate Graph Analysis (Stage 12)
- Maps shared certificate attributes across domains
- Identifies "certificate families" of domains using same issuing patterns
- Tracks certificate issuer migration patterns over time
- Flags domains with suspicious certificate chains
- Adds Signal S17 to threat scoring model (weight: 2.0)

### 4. Infrastructure Timeline Tracking (Integrated with Stage 1)
- Tracks how domains move between hosting providers over time
- Creates infrastructure migration pattern databases
- Identifies "infrastructure hopping" behaviors
- Integrates with certificate timeline analysis

### 5. Multi-Platform IOC Correlation Engine (Stage 14)
- Cross-references discovered IOCs with VirusTotal, AlienVault OTX, URLHaus
- Identifies when domains appear in multiple threat feeds simultaneously
- Creates weighted confidence scoring based on feed consensus
- Adds Signal S16 to threat scoring model (weight: 2.5)

### 6. Social Media & Content Platform Fingerprinting (Stage 15)
- Checks if discovered domains have social media profiles or content platform presence
- Identifies when domains create matching social accounts
- Maps content similarity across platforms
- Adds Signal S18 to threat scoring model (weight: 2.0)

### 7. Cryptocurrency Wallet & Blockchain Intelligence (Stage 16)
- Checks discovered domains for crypto wallet addresses
- Traces wallet funding sources and transaction histories
- Identifies when multiple scam domains feed into same crypto wallets
- Adds Signal S19 to threat scoring model (weight: 3.0)

### 8. Recursive Subdomain Discovery & Brute-forcing (Stage 17)
- Automatically discovers subdomains for high-value targets using multiple techniques
- Maps internal infrastructure structure not visible in public CT logs
- Identifies admin/panel interfaces that suggest deeper access points
- Supports Chinese NEIBU 内部 admin panel detection

### 9. Threat Actor Attribution Pattern Matching (Stage 18)
- Builds behavioral fingerprint databases of known threat actors
- Matches infrastructure patterns to previous campaigns
- Creates confidence-weighted attribution suggestions based on combined signals
- Adds Signal S20 to threat scoring model (weight: 2.5)

### 10. Automated Revalidation & Change Detection
- Schedules recurring checks of discovered infrastructure
- Flags when domains go offline/change hosting/modify infrastructure
- Creates "infrastructure decay" scoring for takedown effectiveness
- Generates alerts for reactivated domains

## Enhanced Settings Management
- Added support for AlienVault OTX API key configuration
- Added support for Censys API key configuration (API_ID:API_SECRET format)
- Added comprehensive infrastructure pivoting feature toggles
- Client-side storage for all settings with server-side API key updates

## API Keys Supported
1. Shodan API Key - Enhanced Shodan intelligence gathering
2. VirusTotal API Key - Passive DNS history and threat feed correlation
3. AlienVault OTX API Key - Threat intelligence correlation
4. Censys API Key (ID:Secret format) - Infrastructure intelligence gathering

## Pipeline Stages
The pipeline has been extended from 7 to 18 stages:
1. Certificate Transparency
2. DNS Resolution
3. IP Intelligence
4. ASN Intelligence Gathering
5. RDAP (Registrar Info)
6. urlscan.io Corroboration
7. JS Wallet Drain Scan
8. Threat Scoring (Initial)
9. Shodan Intelligence
10. VirusTotal Passive DNS
11. Typosquatting Detection
12. SSL Certificate Graph Analysis
13. Reverse IP Lookup Expansion
14. Multi-Platform IOC Correlation
15. Social Media Fingerprinting
16. Cryptocurrency Wallet Intelligence
17. Recursive Subdomain Discovery
18. Threat Actor Attribution

## Threat Scoring Signals
The threat scoring model has been expanded from 12 to 20 signals:

1. Domain cluster volume (weight: 2.0)
2. NEIBU 内部 admin portals (weight: 3.0)
3. Scam-kit naming patterns (weight: 2.5)
4. Chinese cloud infrastructure (weight: 2.0)
5. CDN/cloud origin masking (weight: 1.5)
6. Registrar risk (weight: 1.5)
7. Domain freshness (weight: 1.5)
8. API failover triplet (weight: 1.5)
9. Suspicious infrastructure (weight: 1.5)
10. urlscan.io corroboration (weight: 1.0)
11. JS wallet drain (weight: 3.0)
12. Known operation fingerprint (weight: 3.0)
13. Shannon entropy (weight: 2.0)
14. Shodan open ports (weight: 1.5)
15. VirusTotal passive DNS (weight: 1.5)
16. Typosquatting detection (weight: 2.0)
17. Shared infrastructure patterns (weight: 2.0)
18. Multi-Platform IOC Correlation (weight: 2.5)
19. Cryptocurrency Wallet Intelligence (weight: 3.0)
20. Threat Actor Attribution (weight: 2.5)

## Security Considerations
- All API keys are stored client-side using localStorage
- No sensitive information is exposed in server logs or responses
- Infrastructure is designed for passive OSINT only - no active scanning or probing
- All code follows secure coding practices and avoids exposing secrets

## Version Information
- Application Version: 5.1
- Pipeline Stages: 18
- Threat Scoring Signals: 20
- API Keys Supported: 4 (Shodan, VirusTotal, AlienVault OTX, Censys)
- Infrastructure Pivoting Features: 10
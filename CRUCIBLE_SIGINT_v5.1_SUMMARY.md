# CRUCIBLE SIGINT v5.1 - COMPLETE FEATURE SET

## Summary
CRUCIBLE SIGINT v5.1 represents a significant enhancement to the original 7-stage passive OSINT infrastructure fingerprinting engine. The tool now features 18 pipeline stages and 20 threat scoring signals, with 10 new automated infrastructure pivoting capabilities that enable deeper threat intelligence analysis.

## Core Enhancements

### Enhanced Certificate Transparency (Stage 1)
- Primary source: crt.sh
- Fallback sources: CertSpotter, Bufferover.run
- Integrated certificate timeline analysis
- Integrated infrastructure timeline tracking

### Settings Management
- Client-side API key storage using localStorage
- Server-side API key synchronization via POST endpoints
- Support for Shodan, VirusTotal, AlienVault OTX, and Censys API keys
- Toggle switches for all 10 new infrastructure pivoting features

### New Infrastructure Pivoting Features

1. **Reverse IP Lookup Expansion (Stage 13)**
   - Discovers all domains hosted on same infrastructure
   - Maps hosting provider networks
   - Identifies shared infrastructure patterns
   - Threat Signal S15 (weight: 2.0)

2. **ASN Intelligence Gathering (Stage 4)**
   - Maps IPs to ASNs with detailed intelligence
   - Bulk ASN lookups for efficiency
   - Hosting pattern analysis
   - ASN reputation scoring

3. **SSL Certificate Graph Analysis (Stage 12)**
   - Shared certificate attribute mapping
   - Certificate family identification
   - Issuer migration tracking
   - Suspicious certificate chain flagging
   - Threat Signal S17 (weight: 2.0)

4. **Infrastructure Timeline Tracking**
   - Tracks domain hosting provider changes over time
   - Creates migration pattern databases
   - Identifies infrastructure hopping behaviors

5. **Multi-Platform IOC Correlation (Stage 14)**
   - Cross-references IOCs with VirusTotal, AlienVault OTX, URLHaus
   - Feed consensus scoring
   - Confidence-weighted threat intelligence
   - Threat Signal S16 (weight: 2.5)

6. **Social Media Fingerprinting (Stage 15)**
   - Social media platform presence detection
   - Content platform identification
   - Content similarity mapping
   - Threat Signal S18 (weight: 2.0)

7. **Cryptocurrency Intelligence (Stage 16)**
   - Wallet address detection
   - Wallet funding source tracing
   - Shared wallet infrastructure identification
   - Threat Signal S19 (weight: 3.0)

8. **Subdomain Discovery (Stage 17)**
   - Recursive subdomain enumeration
   - Admin/panel interface identification
   - Internal infrastructure mapping
   - NEIBU 内部 Chinese admin panel detection

9. **Threat Actor Attribution (Stage 18)**
   - Behavioral fingerprint databases
   - Pattern matching against known threat actors
   - Confidence-weighted attribution suggestions
   - Threat Signal S20 (weight: 2.5)

10. **Automated Revalidation**
    - Scheduled infrastructure monitoring
    - Change detection and alerting
    - Infrastructure decay scoring
    - Reactivated domain identification

## API Endpoints

### Enhanced Intelligence Gathering
- `/api/shodan/{ip}` - Shodan intelligence for IPs
- `/api/virustotal/{domain}` - VirusTotal passive DNS history
- `/api/crypto/{domain}` - Cryptocurrency wallet intelligence
- `/api/subdomain/{domain}` - Recursive subdomain discovery

### Settings Management
- `GET /api/settings` - Retrieve current settings configuration
- `POST /api/settings/shodan` - Update Shodan API key
- `POST /api/settings/virustotal` - Update VirusTotal API key
- `POST /api/settings/alienvault` - Update AlienVault OTX API key
- `POST /api/settings/censys` - Update Censys API key

### Automated Revalidation
- `POST /api/revalidation/register/{domain}` - Register domain for monitoring
- `POST /api/revalidation/unregister/{domain}` - Remove domain from monitoring
- `POST /api/revalidation/check/{domain}` - Run immediate revalidation check
- `POST /api/revalidation/run-scheduled` - Execute all scheduled checks
- `GET /api/revalidation/decay-report` - Get infrastructure decay report
- `GET /api/revalidation/alerts` - Get recent alerts
- `GET /api/revalidation/status/{domain}` - Get domain revalidation status

## Security Features
- Client-side API key storage (no server-side persistence)
- No active scanning or probing (passive OSINT only)
- Secure coding practices throughout
- No exposure of secrets in logs or responses

## Version Information
- **Application Version**: 5.1
- **Pipeline Stages**: 18 (originally 7)
- **Threat Scoring Signals**: 20 (originally 12)
- **API Keys Supported**: 4 (Shodan, VirusTotal, AlienVault OTX, Censys)
- **New Infrastructure Pivoting Features**: 10
- **Total Lines of Code**: ~2,100 (app) + ~2,000 (HTML template)

## Files Modified/Added
1. `crucible_app.py` - Main application with all new features
2. `templates/index.html` - Enhanced UI with settings panel and new visualization components
3. `intelligence_extensions.py` - Additional intelligence gathering functions
4. `asn_intelligence.py` - ASN intelligence module
5. `ioc_correlation_engine.py` - Multi-platform IOC correlation engine
6. `threat_actor_attribution.py` - Threat actor attribution module
7. `crypto_intelligence.py` - Cryptocurrency intelligence module
8. `automated_revalidation.py` - Automated revalidation system
9. `infrastructure_timeline.py` - Infrastructure timeline tracking
10. `requirements.txt` - Updated dependencies
11. `README.md` - Updated documentation
12. `API_KEYS.md` - API key configuration guide
13. `ENHANCEMENTS_SUMMARY.md` - Comprehensive enhancement documentation
14. Multiple enhancement documentation files for each new feature

This enhanced version of CRUCIBLE SIGINT maintains the tool's core philosophy of passive OSINT infrastructure fingerprinting while providing significantly expanded capabilities for deeper threat intelligence analysis and infrastructure mapping.
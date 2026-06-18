# Threat Actor Attribution Pattern Matching

## Overview

The Threat Actor Attribution Pattern Matching feature in CRUCIBLE SIGINT v5.1 provides behavioral fingerprint databases of known threat actors, matches infrastructure patterns to previous campaigns, and creates confidence-weighted attribution suggestions based on combined signals.

## Features

### Behavioral Fingerprint Databases

The system includes pre-built fingerprint databases for known threat actors:

1. **DSJ Exchange / BG Wealth Sharing** - $150M cryptocurrency pig-butchering fraud operation
2. **Pig Butchering Scam Kit** - Generic pig-butchering investment fraud infrastructure  
3. **Advanced Phishing Kit A** - Sophisticated phishing infrastructure with rapid rotation

Each fingerprint includes:
- Domain naming patterns
- Infrastructure behaviors and hosting preferences
- SSL certificate issuer patterns
- Social media fingerprints
- JavaScript wallet drain indicators
- IOC patterns and TLD preferences

### Pattern Matching Algorithms

The attribution engine performs multi-dimensional pattern matching:

1. **Domain Naming Analysis** - Matches domain patterns against known threat actor naming conventions
2. **Infrastructure Pattern Analysis** - Correlates hosting providers, ASNs, and geographic patterns
3. **SSL Certificate Analysis** - Identifies certificate issuer patterns and rotation behaviors
4. **Social Media Fingerprinting** - Detects social media platform presence and content patterns
5. **IOC Correlation** - Matches against threat intelligence feeds

### Confidence Scoring

Attribution suggestions include confidence-weighted scoring based on:

- Domain pattern matches (15% weight)
- Infrastructure hopping behaviors (20% weight)
- SSL certificate patterns (10% weight)
- Hosting provider patterns (15% weight)
- ASN patterns (10% weight)
- Geographic patterns (10% weight)
- Social media fingerprints (8% weight)
- IOC correlation (12% weight)

## Integration

The feature is integrated as Stage 17 in the CRUCIBLE pipeline and contributes as Signal #21 in the 17-signal threat scoring model with a weight of 2.5.

## API Endpoints

### Get Threat Actor Fingerprints
```
GET /api/threat-actor-fingerprints
```

Returns the complete threat actor fingerprint database.

### Perform Attribution Analysis
```
POST /api/threat-actor-attribution
{
  "domain": "example.com",
  "analysis_data": {
    "domain_patterns": {...},
    "infrastructure_patterns": {...},
    "certificate_patterns": {...}
  }
}
```

Performs threat actor attribution analysis on provided analysis data.
# Infrastructure Timeline Evolution Tracking

## Overview

The Infrastructure Timeline Evolution Tracking feature in CRUCIBLE SIGINT v5.1 provides advanced capabilities for monitoring how malicious domains move between different hosting providers over time. This functionality complements the existing certificate timeline feature by focusing on infrastructure evolution rather than certificate issuance patterns.

## Key Features

### 1. Hosting Provider Tracking
- Monitors changes in hosting providers for domains over time
- Tracks IP address to ASN (Autonomous System Number) mappings
- Identifies when domains migrate between different providers

### 2. Infrastructure Migration Pattern Databases
- Builds databases of common migration patterns observed across domains
- Identifies frequently used provider transition paths
- Helps detect coordinated infrastructure movements

### 3. Infrastructure Hopping Detection
- Identifies "infrastructure hopping" behaviors where domains frequently change providers
- Scores hopping activity on a 0-100 scale
- Classifies behaviors as:
  - No movement
  - Normal migration
  - Provider diversification
  - Frequent rotation
  - Aggressive hopping

## Technical Implementation

### Core Components

#### infrastructure_timeline.py
This module contains the main functionality for infrastructure tracking:

- `InfrastructureTimeline` class: Main tracking and analysis engine
- `fetch_infrastructure_timeline()`: Main entry point for timeline analysis
- `identify_infrastructure_hopping()`: Hopping behavior detection
- `get_migration_patterns()`: Access to migration pattern database

#### Integration with Existing Modules
- Leverages `asn_intelligence.py` for ASN lookups and provider identification
- Integrates with certificate transparency data from Stage 1
- Utilizes existing HTTP client infrastructure

### Data Flow

1. **Data Collection**: Extract IP history from certificate transparency data
2. **Provider Mapping**: Map IPs to hosting providers via ASN lookups
3. **Timeline Construction**: Build chronological sequence of provider changes
4. **Pattern Analysis**: Identify migration patterns and hopping behaviors
5. **Database Update**: Add new patterns to migration pattern database
6. **Reporting**: Generate timeline and behavioral analysis reports

### Hopping Detection Algorithm

The infrastructure hopping detection uses a weighted scoring system based on:

- **Frequency of changes**: More frequent changes increase the score
- **Provider diversity**: Use of many different providers increases the score
- **Tenure duration**: Short tenure between changes increases the score
- **Datacenter hopping**: Changes between known datacenter providers

Scores are calculated as:
```
score = min(100, (total_changes * 10) + (distinct_providers * 15) + (short_tenure_changes * 20))
```

## Integration with CRUCIBLE Pipeline

### Stage 1 Enhancement
The infrastructure timeline tracking is integrated into Stage 1 (Certificate Transparency) of the standard pipeline:

1. After certificate timeline construction
2. Extract IP history from certificate data
3. Process infrastructure timeline
4. Report findings via SSE events

### SSE Events
- `infraTimeline`: Contains complete infrastructure timeline analysis
- Enhanced logging messages for infrastructure movements

## API and Usage

### Functions

```python
async def fetch_infrastructure_timeline(domain: str, ip_history: List[Dict]) -> Dict
```
Main function for analyzing infrastructure timeline evolution.

```python
def identify_infrastructure_hopping(provider_changes: List[Dict]) -> Dict
```
Identifies infrastructure hopping behaviors from provider change data.

```python
def get_migration_patterns() -> Dict
```
Retrieves database of infrastructure migration patterns.

### Data Structures

#### Infrastructure Timeline Result
```json
{
  "domain": "example.com",
  "infrastructure_timeline": [...],
  "provider_changes": [...],
  "hopping_analysis": {...},
  "migration_patterns": {...},
  "total_movements": 5
}
```

#### Hopping Analysis Result
```json
{
  "hopping_score": 75,
  "indicators": {
    "frequent_changes": 5,
    "short_tenure_changes": 3,
    "distinct_providers": 4,
    "datacenter_hopping": 2
  },
  "behavior": "frequent_rotation",
  "change_count": 5
}
```

## Use Cases

### Threat Intelligence
- Identify infrastructure patterns used by threat actors
- Detect coordinated movements of malicious infrastructure
- Track evolution of attack campaigns

### Investigation Support
- Provide historical context for domain infrastructure
- Support attribution analysis through infrastructure fingerprints
- Enable timeline correlation with other investigative data

### Defensive Applications
- Monitor own domains for unauthorized infrastructure changes
- Detect potential compromise through hosting provider changes
- Alert on suspicious infrastructure movement patterns

## Future Enhancements

### Planned Improvements
1. Integration with additional data sources (VirusTotal, SecurityTrails)
2. Enhanced pattern recognition using machine learning
3. Geographic movement tracking in addition to provider changes
4. Correlation with certificate timeline data for comprehensive analysis

### Advanced Features
1. Predictive modeling for likely future provider changes
2. Group analysis for identifying related infrastructure clusters
3. Integration with threat intelligence feeds for known malicious providers
4. Export functionality for infrastructure timeline reports
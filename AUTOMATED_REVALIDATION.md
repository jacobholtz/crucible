# Automated Revalidation & Change Detection Feature

## Overview
The Automated Revalidation & Change Detection feature is the final infrastructure pivoting enhancement for CRUCIBLE SIGINT v5.1. This feature provides continuous monitoring of discovered infrastructure to detect changes, track infrastructure decay, and generate alerts for reactivated domains.

## Key Capabilities

### 1. Scheduled Recurring Checks
- Automatically schedule periodic checks of discovered domains and infrastructure
- Configurable frequency (default: 24 hours, adjustable per domain)
- Persistent tracking across application restarts

### 2. Change Detection
- DNS resolution status monitoring (online/offline)
- Hosting provider changes detection
- IP address changes tracking
- SSL certificate changes monitoring

### 3. Infrastructure Decay Scoring
- Quantitative scoring system (0-100) for infrastructure decay
- Decay factors:
  - Domain going offline (+30 points)
  - Hosting provider changes (+25 points)
  - IP address changes (+20 points)
  - SSL certificate changes (+15 points)
- Automated takedown effectiveness measurement

### 4. Alert Generation
- Real-time alerts for significant infrastructure changes
- Reactivated domain detection
- Severity-based alerting (low, medium, high, critical)

## API Endpoints

### Register Domain for Monitoring
```
POST /api/revalidation/register/{domain}?frequency_hours=24
```
Register a domain for automated revalidation checks.

### Unregister Domain from Monitoring
```
POST /api/revalidation/unregister/{domain}
```
Remove a domain from automated revalidation checks.

### Run Single Revalidation Check
```
POST /api/revalidation/check/{domain}
```
Perform an immediate revalidation check for a specific domain.

### Run All Scheduled Revalidations
```
POST /api/revalidation/run-scheduled
```
Execute all pending scheduled revalidation checks.

### Get Infrastructure Decay Report
```
GET /api/revalidation/decay-report
```
Retrieve infrastructure decay scores for all monitored domains.

### Get Recent Alerts
```
GET /api/revalidation/alerts?hours=24
```
Fetch recent alerts within the specified time window.

### Get Domain Revalidation Status
```
GET /api/revalidation/status/{domain}
```
Retrieve detailed revalidation status for a specific domain.

## Implementation Details

### Data Storage
- Findings are persisted in `findings_storage.json` by default
- Each domain's status, history, and decay score are tracked
- Alert history is maintained for ongoing monitoring

### Decay Scoring Algorithm
The infrastructure decay score is calculated based on detected changes:
- Domain offline: +30 points
- Hosting provider change: +25 points
- IP address change: +20 points
- SSL certificate change: +15 points
- Maximum score: 100 (complete decay)

### Alert Severity Levels
- **Critical** (70-100): Major infrastructure changes or complete takedowns
- **High** (50-69): Significant changes requiring attention
- **Medium** (30-49): Moderate changes to monitor
- **Low** (<30): Minor changes of minimal concern

## Usage Examples

### Python API Usage
```python
from automated_revalidation import AutomatedRevalidation

# Create revalidation system
revalidation_system = AutomatedRevalidation()

# Register domain for monitoring
revalidation_system.register_domain_for_revalidation("example.com", frequency_hours=12)

# Perform manual check
result = await revalidation_system.perform_revalidation_check("example.com")

# Get decay report
report = revalidation_system.get_decay_report()
```

### Command Line Testing
```bash
# Register a domain for monitoring
curl -X POST "http://localhost:8000/api/revalidation/register/example.com?frequency_hours=24"

# Run a single revalidation check
curl -X POST "http://localhost:8000/api/revalidation/check/example.com"

# Get decay report
curl "http://localhost:8000/api/revalidation/decay-report"
```

## Future Enhancements
- Integration with external monitoring services
- Advanced pattern recognition for infrastructure hopping
- Machine learning-based decay prediction
- Custom decay scoring rules per threat actor
- Integration with SIEM/SOAR platforms

## Integration with Existing Features
The Automated Revalidation system integrates with:
- Infrastructure Timeline tracking for historical change analysis
- ASN Intelligence for hosting provider identification
- Threat scoring for impact assessment
- IOC correlation for comprehensive threat intelligence
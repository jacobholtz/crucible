# Social Media & Content Platform Fingerprinting Enhancement
## For CRUCIBLE SIGINT v5.1

## Feature Overview

This enhancement adds Stage 14 to the CRUCIBLE SIGINT pipeline: **Social Media & Content Platform Fingerprinting**. This feature analyzes discovered domains to identify:

1. **Social Media Presence** - Check if domains match or mimic social media platforms
2. **Content Platform Presence** - Identify domains hosted on content platforms
3. **Content Similarity Mapping** - Map domain naming patterns to identify related content

## Implementation Details

### New Functions Added

1. **`check_social_media_presence(domains: list) -> dict`**
   - Analyzes domain names for social media and content platform indicators
   - Identifies domains that may be impersonating social media platforms
   - Flags suspicious patterns indicating fake social accounts
   - Returns a social platform score based on findings

2. **`map_content_similarity(domains: list) -> dict`**
   - Groups domains by content similarity patterns
   - Identifies common scam naming patterns
   - Calculates content similarity score based on grouping

### New Pipeline Stage (S14)

**Stage 14: Social Media & Content Platform Fingerprinting**
- Analyzes all discovered domains for social media and content platform patterns
- Maps content similarity across the domain cluster
- Provides actionable intelligence on social media fingerprinting
- Scores findings for threat assessment

### New Threat Signal

**Signal: Social Media Fingerprinting** (Weight: 2.0)
- Detects domains that mimic social media platforms
- Identifies content platform presence
- Flags suspicious social media patterns
- Contributes to overall threat scoring with 2.0 weight

## Technical Implementation

### Server-side Changes
- Added `check_social_media_presence()` function for social media analysis
- Added `map_content_similarity()` function for content pattern analysis
- Integrated Social Media Fingerprinting as Stage 14 in standard pipeline
- Added Social Media Fingerprinting signal to threat scoring model
- Added SSE events for frontend integration

### Data Collection
The feature analyzes:
- Domain names for social media platform indicators
- Content platform hosting patterns
- Naming conventions and scam patterns
- Suspicious social media-related domains

### Scoring Logic
Social Media Fingerprinting scores are calculated based on:
- Number of social media domain matches (20 points each)
- Content platform matches (15 points each)
- Suspicious patterns (25 points each)
- Maximum score: 100

## Detection Capabilities

### Social Media Detection
Identifies domains that:
- Match or closely resemble social media platforms
- May be used for impersonation or phishing
- Indicate social engineering infrastructure

### Content Platform Detection
Identifies domains hosted on:
- WordPress, Blogger, Tumblr
- Medium, Wix, Weebly, Squarespace
- Other content management platforms

### Content Similarity Mapping
- Groups domains by common naming patterns
- Identifies scam-related keywords in domain names
- Maps content clusters for infrastructure analysis

## Integration Points

### SSE Events
- `socialMediaData` - Sends social media fingerprinting results to frontend
- Stage 14 activation and completion events
- Detailed logging of findings

### Threat Scoring
- New signal contributes to weighted composite score
- 2.0 weight indicating moderate threat significance
- Factors into overall confidence assessment

## File Modifications

### crucible_app.py
- Added import for new functions
- Added Stage 14 to standard pipeline
- Integrated social media signal into threat scoring
- Updated pipeline initialization message
- Updated skip logic for signal evaluation

### intelligence_extensions.py
- Added `check_social_media_presence()` function
- Added `map_content_similarity()` function

### README.md
- Updated pipeline stages table to include Stage 14
- Updated threat scoring model to 16 signals
- Added Social Media Fingerprinting to feature descriptions

## Benefits

### Enhanced Threat Intelligence
- Identifies social engineering infrastructure
- Detects content platform abuse
- Maps related content clusters

### Infrastructure Analysis
- Expands fingerprinting capabilities beyond technical indicators
- Adds behavioral and content-based threat signals
- Improves correlation of related domains

### Investigative Value
- Provides actionable intelligence on social media impersonation
- Identifies content platform-based campaigns
- Enhances overall threat scoring accuracy

## Future Enhancements

### External API Integration
- Integration with social media platform APIs for verification
- Content analysis of actual social media profiles
- Cross-platform correlation of suspicious accounts

### Advanced Pattern Recognition
- Machine learning-based content similarity detection
- Natural language processing for content analysis
- Image recognition for visual phishing indicators

### Expanded Platform Coverage
- Additional social media and content platforms
- Regional and niche platform support
- Emerging platform monitoring
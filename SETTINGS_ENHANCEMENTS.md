# CRUCIBLE SIGINT - Settings and Enhanced Reliability Features

## Summary of Enhancements

This update adds a Settings page to the CRUCIBLE SIGINT tool and improves the reliability of Certificate Transparency sources.

### New Features

1. **Settings Page**
   - Added a new "SETTINGS" tab to the UI
   - Allows configuration of Shodan and VirusTotal API keys
   - Provides testing functionality for API keys
   - Enables selection of alternative Certificate Transparency sources
   - Includes a "CLEAR ALL SETTINGS" option

2. **Enhanced Certificate Transparency Sources**
   - Added Bufferover.run as a third alternative to crt.sh and CertSpotter
   - Improved fallback mechanism that tries multiple sources in order
   - Made CT source selection configurable through the Settings page

3. **API Key Management**
   - Added server-side endpoints to store and retrieve API keys
   - Implemented client-side storage using localStorage
   - Added testing functionality to verify API key validity

### Technical Implementation

1. **Frontend Changes**
   - Added SETTINGS tab to the HTML interface
   - Created a new mode for settings configuration
   - Implemented JavaScript functions for API key management
   - Added UI elements for CT source selection

2. **Backend Changes**
   - Added API endpoints for settings management
   - Enhanced fetch_crtsh function to support multiple sources
   - Updated phishing and certificate API endpoints to use improved CT sources
   - Added server-side API key storage

3. **Documentation Updates**
   - Updated README.md to document the new Settings mode
   - Added information about alternative Certificate Transparency sources
   - Updated the APIs section to include Bufferover.run

### Benefits

1. **Improved Reliability**
   - Users can now configure alternative CT sources when crt.sh is unavailable
   - Automatic fallback to CertSpotter and Bufferover.run improves data availability

2. **Enhanced Usability**
   - Simplified API key configuration through the Settings page
   - Ability to test API keys directly in the interface
   - Clear visual feedback on API key status

3. **Extended Functionality**
   - Access to additional intelligence sources through Shodan and VirusTotal
   - More comprehensive threat scoring with additional signals
   - Better coverage of malicious infrastructure through multiple CT sources
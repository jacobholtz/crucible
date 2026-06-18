#!/bin/bash

# CRUCIBLE SIGINT Setup Script

echo "=== CRUCIBLE SIGINT Setup ==="

# Check if we're in the right directory
if [ ! -f "crucible_app.py" ]; then
    echo "Error: This script must be run from the crucible-sigint directory"
    exit 1
fi

# Check if Python 3.10+ is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
MAJOR_VERSION=$(echo $PYTHON_VERSION | cut -d. -f1)
MINOR_VERSION=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$MAJOR_VERSION" -gt 3 ] || { [ "$MAJOR_VERSION" -eq 3 ] && [ "$MINOR_VERSION" -ge 10 ]; }; then
    echo "Python version $PYTHON_VERSION is acceptable (3.10+ required)"
else
    echo "Error: Python 3.10 or higher is required (found $PYTHON_VERSION)"
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "Dependencies installed successfully"
else
    echo "Error: Failed to install dependencies"
    exit 1
fi

# Check if API keys are set
echo
echo "Checking for API keys..."
if [ -z "$SHODAN_API_KEY" ]; then
    echo "Warning: SHODAN_API_KEY not set. Shodan integration will be disabled."
    echo "See API_KEYS.md for setup instructions."
fi

if [ -z "$VIRUSTOTAL_API_KEY" ]; then
    echo "Warning: VIRUSTOTAL_API_KEY not set. VirusTotal integration will be disabled."
    echo "See API_KEYS.md for setup instructions."
fi

echo
echo "Setup completed successfully!"
echo "Version 5.1 features:"
echo "  • Enhanced threat scoring with typosquatting detection"
echo "  • DNSTwist integration for brand impersonation detection"
echo "  • New 14-signal threat scoring model"
echo "  • Settings page for API key configuration"
echo "  • Alternative Certificate Transparency sources"
echo
echo "To run the application:"
echo "  python crucible_app.py"
echo
echo "Then open your browser to http://localhost:8000"
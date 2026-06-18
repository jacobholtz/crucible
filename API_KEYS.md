# API Key Setup Guide

To use the enhanced features of CRUCIBLE SIGINT, you'll need to configure API keys for Shodan and VirusTotal. Note that DNSTwist (typosquatting detection) does not require an API key and runs locally.

## Shodan API Key Setup

1. Visit [Shodan.io](https://shodan.io) and create a free account
2. Navigate to your account profile
3. Find your API key in the "API" section
4. Copy the API key

## VirusTotal API Key Setup

1. Visit [VirusTotal](https://virustotal.com) and create a free account
2. Navigate to your account settings
3. Go to the "API Key" section
4. Copy your API key

## Setting API Keys as Environment Variables

### On Linux/macOS:

```bash
export SHODAN_API_KEY="your_shodan_api_key_here"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
```

### On Windows (Command Prompt):

```cmd
set SHODAN_API_KEY=your_shodan_api_key_here
set VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### On Windows (PowerShell):

```powershell
$env:SHODAN_API_KEY="your_shodan_api_key_here"
$env:VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
```

## Running CRUCIBLE with API Keys

After setting the environment variables, start CRUCIBLE as usual:

```bash
python crucible_app.py
```

The tool will automatically detect and use your API keys for enhanced threat intelligence gathering.

Note: Free tier limitations apply to both services:
- Shodan: 50 requests per day
- VirusTotal: 500 requests per day

DNSTwist runs locally and does not have rate limits or require an API key.
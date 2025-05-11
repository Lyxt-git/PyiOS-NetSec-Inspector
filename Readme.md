# IP and DNS Security Monitoring Script

This Python script performs regular checks on your public IP and DNS resolvers. It monitors and classifies the IP and DNS information, providing security insights via Telegram. The tool checks if the current IP is trusted or blacklisted, and whether DNS resolvers are trustworthy or potentially malicious.

## Features:
- Get the public IPv4 address.
- Fetch geolocation information for the public IP.
- Fetch DNS resolver information and classify them as Trusted DNS, Blacklisted DNS, or Unknown DNS.
- Send detailed security alerts via Telegram Bot.
- Supports monitoring for IP and DNS resolver status at regular intervals.
- New : Local IP of GSM which use to connect CGNAT to connected to Internet together with its Ephemeral Port.

## Requirements:
- Python 3.x
- `requests` library (for API calls and HTTP requests)
- `socket` library (for DNS resolution)
- Telegram Bot API Token
- Optional: AbuseIPDB API key, VirusTotal API key (for future use)

## Setup:

### 1. Install Dependencies
Make sure you have the required dependencies installed. You can install them using `pip`:

- pip install requests

## License

This project is open-source and released under the [MIT License](https://mit-license.org/).
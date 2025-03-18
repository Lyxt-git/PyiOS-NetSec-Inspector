NetSec Inspector (Experimental) - Future development may implement SwiftUI for Mobile Applicaiton (iOS)

[Intro]
NetSec-Inspector is a network security monitoring tool designed for iOS. It provides real-time network security insights, including:

[Task]
Monitoring Assigned IP by Carrier, VPN and DNS.
	•	Public IP address detection
	•	DNS resolver monitoring
	•	Threat intelligence lookup (AbuseIPDB)
	•	Telegram alerts for suspicious activity

[Proof-of-Concept]
NetSec Inspector – Proof of Concept (PoC)

[Overview]

This PoC demonstrates the practical feasibility of using OSINT (Open-Source Intelligence) techniques for real-time network security monitoring on iOS (Debug and Compiled via Pyto IDE)

[Objectives]

✅ Monitor public IP changes dynamically.
✅ Identify geolocation data of the public IP (Country, City, ISP, Coordinates).
✅ Classify DNS resolvers as trusted (HNSNS) or untrusted (carrier-assigned).
✅ Check threat intelligence of public IP & DNS via AbuseIPDB.
✅ Send instant Telegram alerts for suspicious activities.

[New Feature]
✅ Add VT API for Detection

[Future Implementation]
✅ Constant Variable read from CSV (Such as Emerging Threat DB List]

[Others]
Information : This is an experimental testing between automatic DNS Assigned and Decentralize DNS Handshake Resolver within HNSNS (Eskimo LLC) run with Carrier and Telegram Bot for Logging for DFIR (in case of BYOD, this script can provide insight of what happen within the BYOD Network Environment) good for Network Forensic and Analysis.

[Documentation]
3rd Party Documentation.
 - HNSNS Docs :
https://hnsns.net/privacy
 - Telegram Bot API : https://core.telegram.org/bots/api

The API variable in this script is Hardcoded (For Testing Only), not recommend in production, you may want to modify it for security.

Usage : 
 - Run Script within Mobile Device that run with Carrier (or Apps if Compiled)
 - Read Logs via Telegram Bot for Security Teams insight.

Idea by : Lyxt @ https://teamsec.carrd.co/

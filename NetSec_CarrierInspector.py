import requests
import time
import socket

# API Keys
BOT_TOKEN = ""  # Replace with your actual Telegram Bot Token
CHAT_ID = ""  # Replace with your actual Telegram Chat ID
ABUSEIPDB_API_KEY = ""  # Replace with your AbuseIPDB API key

# Trusted IPs and DNS
TRUSTED_IPS = ["", ""]  # Trusted Public IPs
HNSNS_DNS = ["", ""]  # Trusted DNS Resolver

def get_public_ipv4():
    """Fetch the public IPv4 address only."""
    urls = [
        "https://api.ipify.org?format=text",  
        "https://ipv4.icanhazip.com",         
        "https://checkip.amazonaws.com",      
    ]

    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except requests.RequestException:
            continue  

    return "Unknown"

def get_geolocation(ip):
    """Get geolocation info for an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,lat,lon", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "fail":
                return "Unknown Location", "N/A", "N/A", "Unknown ISP"
            return f"{data['city']}, {data['regionName']}, {data['country']}", data["lat"], data["lon"], data["isp"]
    except requests.RequestException:
        pass
    return "Unknown Location", "N/A", "N/A", "Unknown ISP"

def get_dns_info():
    """Get the DNS resolver IP addresses."""
    try:
        dns_servers = socket.getaddrinfo("google.com", 80)
        dns_ips = list(set(entry[4][0] for entry in dns_servers))

        trusted_dns = []
        untrusted_dns = []

        for ip in dns_ips:
            if ip == HNSNS_DNS:
                trusted_dns.append(f"{ip} ( HNSNS)")
            else:
                untrusted_dns.append(f"{ip} ( Auto-assigned by Carrier)")

        return dns_ips, trusted_dns, untrusted_dns
    except socket.gaierror:
        return [], ["Unknown"], ["Unknown"]

def check_ip_abuseipdb(ip):
    """Check IP reputation on AbuseIPDB."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY  
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data["data"].get("abuseConfidenceScore", 0), data["data"].get("totalReports", 0)
    except requests.RequestException:
        pass
    return 0, 0  

def send_telegram_message(message):
    """Send a message to Telegram."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    
    try:
        requests.post(url, data=data, timeout=5)
    except requests.RequestException:
        pass  

def monitor_ip_and_dns():
    """Monitor IP and DNS separately and send alerts every 5 seconds."""
    
    # Public IP Check
    current_ip = get_public_ipv4()
    geo_info, latitude, longitude, isp = get_geolocation(current_ip)
    ip_abuse_score, ip_reports = check_ip_abuseipdb(current_ip)

    ip_status = "Trusted IP" if current_ip in TRUSTED_IPS else " Unknown IP"
    ip_threat = f"Abuse Score: {ip_abuse_score}/100 | Reports: {ip_reports}"

    # DNS Check
    dns_ips, trusted_dns, untrusted_dns = get_dns_info()
    dns_threats = []
    
    for dns_ip in dns_ips:
        dns_abuse_score, dns_reports = check_ip_abuseipdb(dns_ip)
        dns_threats.append(f"{dns_ip} ({dns_abuse_score}/100 | Reports: {dns_reports})")

    # Telegram Alert - Show IP and DNS Separately
    alert_message = (
        f"**Current IP & DNS Security Check (OSINT)**\n\n"
        f"**Public IP Details**\n"
        f"{ip_status}\n"
        f"IP: {current_ip}\n"
        f"Location: {geo_info}\n"
        f"ISP: {isp}\n"
        f"Latitude: {latitude}, Longitude: {longitude}\n"
        f"{ip_threat}\n\n"
        
        f"**DNS Resolver Details**\n"
        f"Trusted DNS: {', '.join(trusted_dns)}\n"
        f"Untrusted DNS: {', '.join(untrusted_dns)}\n"
        f"DNS Security: {' | '.join(dns_threats)}\n"
    )
    
    send_telegram_message(alert_message)

# Monitor IP & DNS every 5 seconds
while True:
    monitor_ip_and_dns()
    time.sleep(5)

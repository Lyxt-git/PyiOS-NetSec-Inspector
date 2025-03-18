import requests
import time
import socket

# API Keys
BOT_TOKEN = ""  # Replace with your actual Telegram Bot Token
CHAT_ID = ""  # Replace with your actual Telegram Chat ID
ABUSEIPDB_API_KEY = ""  # Replace with your AbuseIPDB API key
VT_API_KEY = ""  # Replace with your VirusTotal API key

# Trusted & Blacklisted IPs/DNS
TRUSTED_IPS = []  # Add your trusted public IPs if any
HNSNS_DNS = {"142.250.80.110": "Eskimo LLC"}  # Trusted DNS resolver IPs with their provider names
BLACKLISTED_DNS = {""}  # Known bad DNS resolvers

BLACKLISTED_IPS = {""}  # Add known bad IPs

def get_public_ipv4():
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
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,lat,lon", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "fail":
                return "Unknown", "N/A", "N/A", "Unknown ISP"
            return f"{data['city']}, {data['regionName']}, {data['country']}", data["lat"], data["lon"], data["isp"]
    except requests.RequestException:
        pass
    return "Unknown", "N/A", "N/A", "Unknown ISP"

def get_dns_info():
    try:
        dns_servers = socket.getaddrinfo("google.com", 80, socket.AF_INET, socket.SOCK_STREAM)
        dns_ips = list(set(entry[4][0] for entry in dns_servers))
        return dns_ips
    except socket.gaierror:
        return []

def classify_dns_and_ips(dns_ips):
    ip_status_map = {}

    for ip in dns_ips:
        if ip in HNSNS_DNS:
            ip_status_map[ip] = f"🟢 TDNS (HNSDNS {HNSNS_DNS[ip]}) 🟢"
        elif ip in BLACKLISTED_DNS:
            ip_status_map[ip] = f"🔴 BDNS ({BLACKLISTED_DNS[ip]}) 🔴"
        else:
            ip_status_map[ip] = "🟡 UDNS 🟡"

    return ip_status_map

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, data=data, timeout=5)
    except requests.RequestException:
        pass  

def monitor_ip_and_dns():
    current_ip = get_public_ipv4()
    geo_info, latitude, longitude, isp = get_geolocation(current_ip)

    if current_ip in TRUSTED_IPS:
        ip_status = "🟢 TIP 🟢"
    elif current_ip in BLACKLISTED_IPS:
        ip_status = "🔴 BIP! 🔴"
    else:
        ip_status = "🟡 UIP 🟡"

    dns_ips = get_dns_info()
    ip_status_map = classify_dns_and_ips(dns_ips)
    dns_summary = "\n".join(f"🔹 {ip}: {status}" for ip, status in ip_status_map.items())

    alert_message = (
        "🌐 IP & DNS Security Check (OSINT) 🌐\n\n"
        "🔹 Public IP Details :\n"
        f"{ip_status}\n"
        f"🔹 IP: {current_ip}\n"
        f"🔹 Org: {isp}\n"
        f"🔹 LOC: {geo_info}\n"
        f"🔹 LAT: {latitude}, LON: {longitude}\n\n"
        "🔹 DNS Resolver Details :\n"
        f"{dns_summary}\n"
    )
    
    send_telegram_message(alert_message)

while True:
    monitor_ip_and_dns()
    time.sleep(5)
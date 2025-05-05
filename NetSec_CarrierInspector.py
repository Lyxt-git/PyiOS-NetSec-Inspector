import requests
import time
import socket

# API Keys
BOT_TOKEN = ""  # Gantikan dengan Telegram Bot Token anda
CHAT_ID = ""  # Gantikan dengan Chat ID anda
ABUSEIPDB_API_KEY = ""  # Optional: Tambah API key AbuseIPDB jika ingin integrasi
VT_API_KEY = ""  # Optional: VirusTotal API Key

# Senarai IP/DNS dipercayai & disenarai hitam
TRUSTED_IPS = []
HNSNS_DNS = {"": "Eskimo LLC"}
BLACKLISTED_DNS = {""}
BLACKLISTED_IPS = {""}

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

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))  # Fake connection to detect interface
        ip = s.getsockname()[0]
    except Exception:
        ip = 'N/A'
    finally:
        s.close()
    return ip

def get_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(('0.0.0.0', 0))  # Bind to any available port
        local_port = s.getsockname()[1]
    except Exception:
        local_port = 'N/A'
    finally:
        s.close()
    return local_port

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
    local_ip = get_local_ip()
    local_port = get_local_port()
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
        "🌐 *IP & DNS Security Check (OSINT)* 🌐\n\n"
        f"🔹 *Local IP* : `{local_ip}`\n"
        f"🔹 *Local Port* : `{local_port}`\n"
        f"🔹 *Public IP* : `{current_ip}`\n"
        f"{ip_status}\n"
        f"🔹 *ISP* : {isp}\n"
        f"🔹 *Location* : {geo_info}\n"
        f"🔹 *LAT/LON* : {latitude}, {longitude}\n\n"
        f"🔹 *DNS Resolvers* :\n{dns_summary}\n"
    )
    
    send_telegram_message(alert_message)

while True:
    monitor_ip_and_dns()
    time.sleep(5)
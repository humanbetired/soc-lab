import requests
import json
import subprocess
import warnings
from datetime import datetime
import os

warnings.filterwarnings('ignore')

# ── KONFIGURASI ──────────────────────────────────────
WAZUH_HOST = "https://localhost:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "Wazuh1313*"
ALERT_LOG  = "/var/ossec/logs/alerts/alerts.json"
REPORT_DIR = "/home/wazuh/soc-project/reports"
# ─────────────────────────────────────────────────────

def get_token():
    url = f"{WAZUH_HOST}/security/user/authenticate"
    response = requests.post(url, auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    token = response.json()["data"]["token"]
    print("[+] Login ke Wazuh API berhasil")
    return token

def get_brute_force_alerts():
    result = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"60122"|"id":"60115"', ALERT_LOG],
        capture_output=True, text=True
    )
    alerts = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                alerts.append(json.loads(line))
            except:
                pass
    return alerts

def parse_alerts(alerts):
    ip_data = {}
    for alert in alerts:
        eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
        rule_id   = alert.get("rule", {}).get("id", "")
        timestamp = alert.get("timestamp", "")

        # Ambil IP attacker — coba beberapa field
        src_ip = (
            eventdata.get("ipAddress") or
            eventdata.get("sourceNetworkAddress") or
            eventdata.get("sourceAddress") or
            alert.get("data", {}).get("srcip") or
            "Kali-192.168.1.12"   # fallback label jika SSH tidak log IP
        )

        # Ambil username yang diserang
        username = (
            eventdata.get("targetUserName") or
            alert.get("data", {}).get("dstuser") or
            "Unknown"
        )

        # Ambil logon type (8 = NetworkCleartext = SSH)
        logon_type = eventdata.get("logonType", "")
        logon_desc = {
            "2": "Interactive",
            "3": "Network",
            "8": "NetworkCleartext (SSH)",
            "10": "RemoteInteractive (RDP)"
        }.get(logon_type, f"Type {logon_type}")

        if src_ip not in ip_data:
            ip_data[src_ip] = {
                "count":      0,
                "locked":     False,
                "usernames":  set(),
                "logon_type": logon_desc,
                "first_seen": timestamp,
                "last_seen":  timestamp,
            }

        ip_data[src_ip]["count"] += 1
        ip_data[src_ip]["usernames"].add(username)
        ip_data[src_ip]["last_seen"] = timestamp

        if rule_id == "60115":
            ip_data[src_ip]["locked"] = True

    return ip_data

def get_severity(count, locked):
    if locked or count >= 10:
        return "CRITICAL", "🔴"
    elif count >= 5:
        return "HIGH",     "🟠"
    else:
        return "MEDIUM",   "🟡"

def build_report_lines(ip_data, total_alerts, now):
    lines = []
    lines.append(f"{'='*62}")
    lines.append(f"  WAZUH SOC — BRUTE FORCE ALERT REPORT")
    lines.append(f"  Generated : {now}")
    lines.append(f"{'='*62}")
    lines.append(f"  Total alert   : {total_alerts}")
    lines.append(f"  Unique source : {len(ip_data)} IP(s)")
    lines.append(f"{'='*62}")
    lines.append("")

    for ip, info in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True):
        severity, icon = get_severity(info['count'], info['locked'])
        users = ', '.join(info['usernames']) if info['usernames'] else 'Unknown'
        lines.append(f"  {icon}  Severity    : {severity}")
        lines.append(f"     Source IP   : {ip}")
        lines.append(f"     Attempts    : {info['count']}")
        lines.append(f"     Target user : {users}")
        lines.append(f"     Logon type  : {info['logon_type']}")
        lines.append(f"     Locked out  : {'YES ⚠️' if info['locked'] else 'No'}")
        lines.append(f"     First seen  : {info['first_seen']}")
        lines.append(f"     Last seen   : {info['last_seen']}")
        lines.append(f"     Action      : {'BLOCK IP + UNLOCK ACCOUNT' if info['locked'] else 'Block IP immediately'}")
        lines.append(f"  {'─'*54}")

    return lines

def print_report(lines):
    for line in lines:
        print(line)

def save_report(lines):
    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"{REPORT_DIR}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    clean_lines = []
    for line in lines:
        for emoji in ['🔴','🟠','🟡','⚠️']:
            line = line.replace(emoji, '')
    clean_lines.append(line)
    with open(filename, 'w') as f:
        f.write('\n'.join(clean_lines))
    print(f"\n[+] Laporan disimpan: {filename}")
    return filename

if __name__ == "__main__":
    print("[*] Menghubungkan ke Wazuh API...")
    token = get_token()

    print("[*] Mengambil alert brute force dari log...")
    alerts = get_brute_force_alerts()

    if not alerts:
        print("[-] Tidak ada alert brute force ditemukan")
        print("[~] Tip: Jalankan simulasi Hydra terlebih dahulu")
        exit(0)

    ip_data = parse_alerts(alerts)
    now     = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines   = build_report_lines(ip_data, len(alerts), now)

    print_report(lines)
    save_report(lines)

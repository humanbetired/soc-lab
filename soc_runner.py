import requests
import anthropic
import json
import subprocess
import warnings
import os
from datetime import datetime

warnings.filterwarnings('ignore')

# ── KONFIGURASI ──────────────────────────────────────
WAZUH_HOST = "https://localhost:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "Wazuh1313*"
ALERT_LOG  = "/var/ossec/logs/alerts/alerts.json"
REPORT_DIR = "/home/wazuh/soc-project/reports"
API_KEY    = os.environ.get("ANTHROPIC_API_KEY")
# ─────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           WAZUH SOC AUTOMATED RESPONSE SYSTEM               ║
║           Powered by Claude AI + Wazuh SIEM                 ║
╚══════════════════════════════════════════════════════════════╝
"""

def step(msg):
    print(f"\n[→] {msg}")

def ok(msg):
    print(f"[✓] {msg}")

def warn(msg):
    print(f"[!] {msg}")

# ─── STEP 1: LOGIN WAZUH API ─────────────────────────────────
def get_token():
    step("Login ke Wazuh API...")
    url = f"{WAZUH_HOST}/security/user/authenticate"
    response = requests.post(url, auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    token = response.json()["data"]["token"]
    ok("Login berhasil")
    return token

# ─── STEP 2: AMBIL ALERT ─────────────────────────────────────
def get_alerts():
    step("Mengambil alert brute force dari log...")
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
    ok(f"{len(alerts)} alert ditemukan")
    return alerts

# ─── STEP 3: PARSE & TRIAGE ──────────────────────────────────
def parse_alerts(alerts):
    step("Melakukan triage alert...")
    ip_data = {}
    for alert in alerts:
        eventdata  = alert.get("data", {}).get("win", {}).get("eventdata", {})
        rule_id    = alert.get("rule", {}).get("id", "")
        timestamp  = alert.get("timestamp", "")
        username   = eventdata.get("targetUserName") or "Unknown"
        logon_type = eventdata.get("logonType", "")

        src_ip = (
            eventdata.get("ipAddress") or
            eventdata.get("sourceNetworkAddress") or
            "192.168.1.12"
        )

        if src_ip not in ip_data:
            ip_data[src_ip] = {
                "count": 0,
                "locked": False,
                "usernames": set(),
                "logon_type": logon_type,
                "first_seen": timestamp,
                "last_seen": timestamp,
            }

        ip_data[src_ip]["count"] += 1
        ip_data[src_ip]["usernames"].add(username)
        ip_data[src_ip]["last_seen"] = timestamp
        if rule_id == "60115":
            ip_data[src_ip]["locked"] = True

    ok(f"Triage selesai — {len(ip_data)} unique IP")
    return ip_data

# ─── STEP 4: SEVERITY SCORING ────────────────────────────────
def get_severity(count, locked):
    if locked or count >= 10:
        return "CRITICAL", "🔴"
    elif count >= 5:
        return "HIGH",     "🟠"
    else:
        return "MEDIUM",   "🟡"

# ─── STEP 5: AUTO-BLOCK VIA ACTIVE RESPONSE ──────────────────
def block_ip(token, ip, count, locked):
    severity, icon = get_severity(count, locked)

    if severity not in ("CRITICAL", "HIGH"):
        warn(f"IP {ip} severity {severity} — skip auto-block")
        return False

    step(f"Auto-blocking IP {ip} via Wazuh Active Response...")
    headers = {"Authorization": f"Bearer {token}"}
    url     = f"{WAZUH_HOST}/active-response"

    payload = {
        "command":   "firewall-drop600",
        "arguments": [ip],
        "alert": {
            "data": {
                "srcip": ip
            }
        }
    }

    response = requests.put(url, headers=headers, json=payload, verify=False)
    result   = response.json()

    if response.status_code == 200:
        ok(f"IP {ip} berhasil diblok! (timeout: 600 detik)")
        return True
    else:
        warn(f"Auto-block gagal: {result}")
        return False

# ─── STEP 6: PRINT ALERT REPORT ──────────────────────────────
def print_alert_report(ip_data, total):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n{'='*62}")
    print(f"  WAZUH SOC — BRUTE FORCE ALERT REPORT")
    print(f"  Generated : {now}")
    print(f"{'='*62}")
    print(f"  Total alert   : {total}")
    print(f"  Unique source : {len(ip_data)} IP(s)")
    print(f"{'='*62}")

    for ip, info in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True):
        severity, icon = get_severity(info['count'], info['locked'])
        users = ', '.join(info['usernames'])
        print(f"\n  {icon}  Severity    : {severity}")
        print(f"     Source IP   : {ip}")
        print(f"     Attempts    : {info['count']}")
        print(f"     Target user : {users}")
        print(f"     Locked out  : {'YES ⚠️' if info['locked'] else 'No'}")
        print(f"     First seen  : {info['first_seen']}")
        print(f"     Last seen   : {info['last_seen']}")
        print(f"  {'─'*54}")
    return now

# ─── STEP 7: AI INVESTIGATION ────────────────────────────────
def analyze_with_claude(ip_data, total):
    step("Mengirim data ke Claude AI untuk investigasi...")

    if not API_KEY:
        warn("ANTHROPIC_API_KEY tidak ditemukan, skip AI analysis")
        return None

    summary = []
    for ip, info in ip_data.items():
        severity, _ = get_severity(info['count'], info['locked'])
        summary.append({
            "source_ip":      ip,
            "attempts":       info['count'],
            "locked_out":     info['locked'],
            "targeted_users": list(info['usernames']),
            "logon_type":     info['logon_type'],
            "first_seen":     info['first_seen'],
            "last_seen":      info['last_seen'],
            "severity":       severity,
        })

    client = anthropic.Anthropic(api_key=API_KEY)
    prompt = f"""Kamu adalah SOC Analyst senior. Berikut data alert brute force SSH dari Wazuh SIEM:

{json.dumps(summary, indent=2)}

Buatkan laporan investigasi SOC profesional dalam Bahasa Indonesia yang mencakup:

1. EXECUTIVE SUMMARY — ringkasan singkat insiden
2. DETAIL INSIDEN — jenis serangan, timeline, source/target
3. ANALISIS ANCAMAN — severity, MITRE ATT&CK, potensi dampak
4. REKOMENDASI TINDAKAN — immediate action + preventive
5. KESIMPULAN

Format rapi dan profesional seperti laporan SOC sungguhan."""

    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    ok("Analisis AI selesai")
    return message.content[0].text

# ─── STEP 8: SIMPAN LAPORAN ──────────────────────────────────
def save_reports(ip_data, total, alert_now, ai_report):
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Alert report
    alert_file = f"{REPORT_DIR}/alert_{ts}.txt"
    with open(alert_file, 'w') as f:
        f.write(f"WAZUH SOC — BRUTE FORCE ALERT REPORT\n")
        f.write(f"Generated: {alert_now}\n")
        f.write(f"{'='*62}\n")
        f.write(f"Total alert   : {total}\n")
        f.write(f"Unique source : {len(ip_data)} IP(s)\n\n")
        for ip, info in ip_data.items():
            severity, _ = get_severity(info['count'], info['locked'])
            f.write(f"Severity   : {severity}\n")
            f.write(f"Source IP  : {ip}\n")
            f.write(f"Attempts   : {info['count']}\n")
            f.write(f"Users      : {', '.join(info['usernames'])}\n")
            f.write(f"Locked     : {'YES' if info['locked'] else 'No'}\n")
            f.write(f"First seen : {info['first_seen']}\n")
            f.write(f"Last seen  : {info['last_seen']}\n\n")
    ok(f"Alert report: {alert_file}")

    # AI report
    if ai_report:
        ai_file = f"{REPORT_DIR}/ai_report_{ts}.md"
        with open(ai_file, 'w') as f:
            f.write(f"# SOC AI Investigation Report\n")
            f.write(f"Generated: {alert_now}\n\n")
            f.write(ai_report)
        ok(f"AI report   : {ai_file}")

# ─── TELEGRAM NOTIFIKASI ─────────────────────────────────
def send_telegram(message):
    token   = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        warn("Telegram credentials tidak ditemukan, skip notifikasi")
        return False

    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "Markdown"
    }

    try:
        r = requests.post(url, json=data, timeout=10)
        if r.status_code == 200:
            ok("Notifikasi Telegram terkirim!")
            return True
        else:
            warn(f"Telegram gagal: {r.text}")
            return False
    except Exception as e:
        warn(f"Telegram error: {e}")
        return False


def build_telegram_message(ip_data, total, blocked):
    lines = []
    lines.append("🚨 *WAZUH SOC ALERT*")
    lines.append(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"📊 *Summary*")
    lines.append(f"• Total attempts : `{total}`")
    lines.append(f"• Unique IPs     : `{len(ip_data)}`")
    lines.append(f"• IPs diblok     : `{len(blocked)}`")
    lines.append("")

    for ip, info in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True):
        severity = get_severity(info['count'], info['locked'])[0]
        icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
        users = ', '.join(info['usernames'])
        lines.append(f"{icon} *{severity}* — `{ip}`")
        lines.append(f"• Attempts   : `{info['count']}`")
        lines.append(f"• Target     : `{users}`")
        lines.append(f"• Locked out : `{'YES ⚠️' if info['locked'] else 'No'}`")
        lines.append(f"• Action     : `{'BLOCKED' if ip in blocked else 'MONITOR'}`")
        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("_Powered by Wazuh SIEM + Claude AI_")
    return "\n".join(lines)

# ─── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    print(BANNER)

    # Step 1 — Auth
    token = get_token()

    # Step 2 — Fetch alerts
    alerts = get_alerts()
    if not alerts:
        warn("Tidak ada alert ditemukan. Jalankan simulasi Hydra terlebih dahulu.")
        exit(0)

    # Step 3 — Triage
    ip_data = parse_alerts(alerts)

    # Step 4 & 5 — Score + Auto-block
    step("Evaluasi dan auto-block IP berbahaya...")
    blocked = []
    for ip, info in ip_data.items():
        was_blocked = block_ip(token, ip, info['count'], info['locked'])
        if was_blocked:
            blocked.append(ip)

    if blocked:
        ok(f"{len(blocked)} IP diblok: {', '.join(blocked)}")
    else:
        warn("Tidak ada IP yang diblok")

    # Step 6 — Print report
    alert_now = print_alert_report(ip_data, len(alerts))

    # Step 7 — AI analysis
    ai_report = analyze_with_claude(ip_data, len(alerts))
    if ai_report:
        print(f"\n{'='*62}")
        print("  CLAUDE AI — SOC INVESTIGATION REPORT")
        print(f"{'='*62}")
        print(ai_report)

    # Step 8 — Save
    step("Menyimpan semua laporan...")
    save_reports(ip_data, len(alerts), alert_now, ai_report)

    # Step 9 — Telegram
    step("Mengirim notifikasi Telegram...")
    tg_msg = build_telegram_message(ip_data, len(alerts), blocked)
    send_telegram(tg_msg)

    print(f"\n{'='*62}")
    print(f"  SELESAI — SOC automated response complete")
    print(f"  Blocked IPs : {len(blocked)}")
    print(f"  Reports     : {REPORT_DIR}")
    print(f"{'='*62}\n")



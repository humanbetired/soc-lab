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
    # Brute force SSH
    result_ssh = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"60122"|"id":"60115"', ALERT_LOG],
        capture_output=True, text=True
    )
    # Web attacks (SQLi)
    result_web = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"31103"|"id":"31104"|"id":"31105"|"id":"31152"|"id":"31170"|"id":"31171"', ALERT_LOG],
        capture_output=True, text=True
    )

    alerts_ssh = []
    for line in result_ssh.stdout.strip().split('\n'):
        if line:
            try:
                a = json.loads(line)
                a['_attack_type'] = 'brute_force'
                alerts_ssh.append(a)
            except:
                pass

    alerts_web = []
    for line in result_web.stdout.strip().split('\n'):
        if line:
            try:
                a = json.loads(line)
                a['_attack_type'] = 'web_attack'
                alerts_web.append(a)
            except:
                pass

    result_privesc = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"61618"|"id":"61634"|"id":"61638"|"id":"61138"|"id":"100001"|"id":"100002"|"id":"100003"', ALERT_LOG],
        capture_output=True, text=True
    )
    alerts_privesc = []
    for line in result_privesc.stdout.strip().split('\n'):
        if line:
            try:
                a = json.loads(line)
                a['_attack_type'] = 'privesc'
                alerts_privesc.append(a)
            except: pass

    result_smb = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"92652"|"id":"60104"|"id":"60205"', ALERT_LOG],
        capture_output=True, text=True
    )
    alerts_smb = []
    for line in result_smb.stdout.strip().split('\n'):
        if line:
            try:
                a = json.loads(line)
                a['_attack_type'] = 'smb'
                alerts_smb.append(a)
            except: pass

    ok(f"{len(alerts_ssh)} SSH | {len(alerts_web)} web | {len(alerts_privesc)} privesc | {len(alerts_smb)} SMB alert")
    return alerts_ssh + alerts_web + alerts_privesc + alerts_smb

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

def parse_web_alerts(alerts):
    """Parse web attack alerts."""
    ip_data = {}
    for alert in [a for a in alerts if a.get('_attack_type') == 'web_attack']:
        src_ip    = alert.get('data', {}).get('srcip', 'Unknown')
        url       = alert.get('data', {}).get('url', '')
        rule_id   = alert.get('rule', {}).get('id', '')
        rule_desc = alert.get('rule', {}).get('description', '')
        timestamp = alert.get('timestamp', '')

        # Kategorikan jenis serangan
        if rule_id in ('31103', '31152', '31170', '31171'):
            attack_cat = 'SQL Injection'
        elif rule_id == '31105':
            attack_cat = 'XSS'
        elif rule_id == '31104':
            attack_cat = 'Common Web Attack'
        elif rule_id == '31120':
            attack_cat = 'LFI'
        else:
            attack_cat = 'Web Attack'
        if src_ip not in ip_data:
            ip_data[src_ip] = {
                'count':      0,
                'categories': set(),
                'urls':       [],
                'first_seen': timestamp,
                'last_seen':  timestamp,
            }

        ip_data[src_ip]['count'] += 1
        ip_data[src_ip]['categories'].add(attack_cat)
        if url not in ip_data[src_ip]['urls']:
            ip_data[src_ip]['urls'].append(url)
        ip_data[src_ip]['last_seen'] = timestamp

    # Convert set to list
    for ip in ip_data:
        ip_data[ip]['categories'] = list(ip_data[ip]['categories'])

    return ip_data

# ─── STEP 4: SEVERITY SCORING ────────────────────────────────

def parse_privesc_alerts(alerts):
    ip_data = {}
    for alert in [a for a in alerts if a.get('_attack_type') == 'privesc']:
        agent   = alert.get('agent', {}).get('name', 'Unknown')
        rule_id = alert.get('rule', {}).get('id', '')
        ts      = alert.get('timestamp', '')
        proc    = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('image', '')

        if agent not in ip_data:
            ip_data[agent] = {
                'count':      0,
                'processes':  set(),
                'rule_ids':   set(),
                'first_seen': ts,
                'last_seen':  ts,
            }
        ip_data[agent]['count'] += 1
        ip_data[agent]['rule_ids'].add(rule_id)
        if proc:
            ip_data[agent]['processes'].add(proc.split('\\')[-1])
        ip_data[agent]['last_seen'] = ts

    for agent in ip_data:
        ip_data[agent]['processes'] = list(ip_data[agent]['processes'])
        ip_data[agent]['rule_ids']  = list(ip_data[agent]['rule_ids'])
    return ip_data


def parse_smb_alerts(alerts):
    """Parse SMB attack alerts."""
    ip_data = {}
    for alert in [a for a in alerts if a.get('_attack_type') == 'smb']:
        eventdata = alert.get('data', {}).get('win', {}).get('eventdata', {})
        rule_id   = alert.get('rule', {}).get('id', '')
        timestamp = alert.get('timestamp', '')

        src_ip = (
            eventdata.get('ipAddress') or
            eventdata.get('sourceNetworkAddress') or
            'Unknown'
        )
        username = (
            eventdata.get('subjectUserName') or
            eventdata.get('targetUserName') or
            'Unknown'
        )
        share = eventdata.get('shareName', 'Unknown')

        if src_ip not in ip_data:
            ip_data[src_ip] = {
                'count':      0,
                'usernames':  set(),
                'shares':     set(),
                'anonymous':  False,
                'first_seen': timestamp,
                'last_seen':  timestamp,
            }

        ip_data[src_ip]['count'] += 1
        ip_data[src_ip]['usernames'].add(username)
        if share and share != 'Unknown':
            ip_data[src_ip]['shares'].add(share)
        if 'ANONYMOUS' in username.upper():
            ip_data[src_ip]['anonymous'] = True
        ip_data[src_ip]['last_seen'] = timestamp

    for ip in ip_data:
        ip_data[ip]['usernames'] = list(ip_data[ip]['usernames'])
        ip_data[ip]['shares']    = list(ip_data[ip]['shares'])

    return ip_data

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
        print(f"     Locked out  : {'YES' if info['locked'] else 'No'}")
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
    lines.append("*WAZUH SOC ALERT*")
    lines.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"*Summary*")
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
        lines.append(f"• Locked out : `{'YES' if info['locked'] else 'No'}`")
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
    # Web attack report
    web_data = parse_web_alerts(alerts)
    if web_data:
        print(f"\n{'='*62}")
        print(f"  WEB ATTACK REPORT")
        print(f"{'='*62}")
        for ip, info in web_data.items():
            severity = "CRITICAL" if info['count'] >= 50 else "HIGH" if info['count'] >= 10 else "MEDIUM"
            icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            print(f"\n  {icon}  Severity   : {severity}")
            print(f"     Source IP  : {ip}")
            print(f"     Attempts   : {info['count']}")
            print(f"     Categories : {', '.join(info['categories'])}")
            print(f"     First seen : {info['first_seen'][:19]}")
            print(f"     Last seen  : {info['last_seen'][:19]}")
            print(f"  {'─'*54}")
    # Step 7 — AI analysis
    ai_report = analyze_with_claude(ip_data, len(alerts))
    if ai_report:
        print(f"\n{'='*62}")
        print("  CLAUDE AI — SOC INVESTIGATION REPORT")
        print(f"{'='*62}")
        print(ai_report)

    # Privesc report
    privesc_data = parse_privesc_alerts(alerts)
    if privesc_data:
        print(f"\n{'='*62}")
        print(f"  PRIVILEGE ESCALATION REPORT")
        print(f"{'='*62}")
        for agent, info in privesc_data.items():
            severity = "CRITICAL" if info['count'] >= 10 else "HIGH" if info['count'] >= 5 else "MEDIUM"
            icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            procs = ', '.join(info['processes'][:5]) if info['processes'] else 'Unknown'
            print(f"\n  {icon}  Severity    : {severity}")
            print(f"     Agent      : {agent}")
            print(f"     Events     : {info['count']}")
            print(f"     Processes  : {procs}")
            print(f"     First seen : {info['first_seen'][:19]}")
            print(f"     Last seen  : {info['last_seen'][:19]}")
            print(f"  {'─'*54}")

    # SMB report
    smb_data = parse_smb_alerts(alerts)
    if smb_data:
        print(f"\n{'='*62}")
        print(f"  SMB ATTACK REPORT")
        print(f"{'='*62}")
        for ip, info in smb_data.items():
            severity = "CRITICAL" if info['anonymous'] or info['count'] >= 10 else "HIGH" if info['count'] >= 5 else "MEDIUM"
            icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            users  = ', '.join(info['usernames'][:3])
            shares = ', '.join(info['shares'][:3]) if info['shares'] else 'None detected'
            print(f"\n  {icon}  Severity    : {severity}")
            print(f"     Source IP   : {ip}")
            print(f"     Attempts    : {info['count']}")
            print(f"     Users       : {users}")
            print(f"     Shares      : {shares}")
            print(f"     Anonymous   : {'YES ⚠️' if info['anonymous'] else 'No'}")
            print(f"     First seen  : {info['first_seen'][:19]}")
            print(f"     Last seen   : {info['last_seen'][:19]}")
            print(f"  {'─'*54}")

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



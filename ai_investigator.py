import anthropic
import json
import subprocess
import os
from datetime import datetime

# ── KONFIGURASI ──────────────────────────────────────
ALERT_LOG  = "/var/ossec/logs/alerts/alerts.json"
REPORT_DIR = "/home/wazuh/soc-project/reports"
API_KEY    = os.environ.get("ANTHROPIC_API_KEY")
# ─────────────────────────────────────────────────────

def get_brute_force_alerts():
    """Ambil alert brute force dari log."""
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

def build_alert_summary(alerts):
    """Buat ringkasan alert untuk dikirim ke Claude."""
    ip_data = {}
    for alert in alerts:
        eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
        rule_id   = alert.get("rule", {}).get("id", "")
        timestamp = alert.get("timestamp", "")
        username  = eventdata.get("targetUserName") or "Unknown"
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
                "first_seen": timestamp,
                "last_seen": timestamp,
                "logon_type": logon_type,
            }

        ip_data[src_ip]["count"] += 1
        ip_data[src_ip]["usernames"].add(username)
        ip_data[src_ip]["last_seen"] = timestamp
        if rule_id == "60115":
            ip_data[src_ip]["locked"] = True

    summary = []
    for ip, info in ip_data.items():
        summary.append({
            "source_ip": ip,
            "attempts": info["count"],
            "locked_out": info["locked"],
            "targeted_users": list(info["usernames"]),
            "logon_type": info["logon_type"],
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
        })
    return summary

def analyze_with_claude(alert_summary):
    """Kirim data alert ke Claude untuk dianalisis."""
    client = anthropic.Anthropic(api_key=API_KEY)

    prompt = f"""Kamu adalah SOC Analyst senior. Berikut adalah data alert brute force SSH yang terdeteksi oleh Wazuh SIEM:

{json.dumps(alert_summary, indent=2)}

Buatkan laporan investigasi SOC profesional dalam Bahasa Indonesia yang mencakup:

1. EXECUTIVE SUMMARY
   - Ringkasan singkat insiden

2. DETAIL INSIDEN
   - Jenis serangan
   - Waktu serangan (first seen - last seen)
   - Source IP dan target
   - Jumlah percobaan
   - Apakah berhasil locked out

3. ANALISIS ANCAMAN
   - Tingkat keparahan (severity)
   - Teknik yang digunakan (MITRE ATT&CK jika relevan)
   - Potensi dampak

4. REKOMENDASI TINDAKAN
   - Tindakan segera (immediate action)
   - Tindakan jangka panjang (preventive)

5. KESIMPULAN

Format laporan harus rapi dan profesional seperti laporan SOC sungguhan."""

    print("[*] Mengirim data ke Claude AI untuk dianalisis...")
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2000,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    return message.content[0].text

def save_ai_report(report_text):
    """Simpan laporan AI ke file."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"{REPORT_DIR}/ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, 'w') as f:
        f.write(f"# SOC AI Investigation Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(report_text)
    print(f"\n[+] AI Report disimpan: {filename}")
    return filename

if __name__ == "__main__":
    print("[*] Mengambil alert dari Wazuh log...")
    alerts = get_brute_force_alerts()

    if not alerts:
        print("[-] Tidak ada alert ditemukan")
        exit(0)

    print(f"[+] {len(alerts)} alert ditemukan, memproses...")
    summary = build_alert_summary(alerts)

    print("[*] Memulai analisis AI...")
    report = analyze_with_claude(summary)

    print("\n" + "="*62)
    print("  CLAUDE AI — SOC INVESTIGATION REPORT")
    print("="*62)
    print(report)

    save_ai_report(report)

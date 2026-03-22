# 🛡️ SOC Analyst Portfolio Lab

> **Simulasi lingkungan Security Operations Center (SOC) berbasis Wazuh SIEM dengan otomatisasi Python, integrasi Claude AI, dashboard web real-time, dan notifikasi Telegram — mencakup 5 jenis serangan berbeda.**

---

## 📋 Daftar Isi

- [Tentang Project](#-tentang-project)
- [Arsitektur Sistem](#-arsitektur-sistem)
- [Fitur Utama](#-fitur-utama)
- [Attack Coverage](#-attack-coverage)
- [Tech Stack](#-tech-stack)
- [Struktur Project](#-struktur-project)
- [Setup & Instalasi](#-setup--instalasi)
- [Cara Penggunaan](#-cara-penggunaan)
- [Dashboard](#-dashboard)
- [Hasil & Temuan](#-hasil--temuan)
- [Kontak](#-kontak)

---

## 📌 Tentang Project

Project ini merupakan simulasi lingkungan SOC yang dibangun untuk keperluan portofolio sebagai **SOC Analyst**. Lab ini mensimulasikan skenario serangan nyata, mendeteksinya menggunakan Wazuh SIEM, lalu merespons secara otomatis menggunakan kombinasi Python, Claude AI, Wazuh Active Response, dan Telegram Bot.

### Tujuan
- Membangun pemahaman end-to-end tentang alur kerja SOC
- Mensimulasikan 5 jenis serangan nyata dan mendeteksinya
- Mengotomatisasi proses triage, response, dan pelaporan
- Mengintegrasikan AI untuk menghasilkan laporan investigasi profesional

---

## 🏗️ Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────────┐
│                      NETWORK TOPOLOGY                           │
│                     192.168.1.0/24                              │
│                                                                 │
│  ┌──────────────┐   Multiple Attacks   ┌─────────────────────┐ │
│  │  Kali Linux  │ ──────────────────► │   Windows 11        │ │
│  │  (Attacker)  │  SSH/RDP/SMB/Web    │   (Target)          │ │
│  │ 192.168.1.12 │                     │   192.168.1.11      │ │
│  └──────────────┘                     │   Wazuh Agent       │ │
│                                       │   XAMPP + DVWA      │ │
│                                       │   Sysmon            │ │
│                                       └──────────┬──────────┘ │
│                                                  │             │
│                                       ┌──────────▼──────────┐ │
│                                       │   Lubuntu Server    │ │
│                                       │   192.168.1.10      │ │
│                                       │   Wazuh SIEM 4.7.5  │ │
│                                       │   Python Automation │ │
│                                       │   Flask Dashboard   │ │
│                                       └──────────┬──────────┘ │
└──────────────────────────────────────────────────┼────────────┘
                                                   │
                    ┌──────────────────────────────┼─────────────┐
                    │                              │             │
                    ▼                              ▼             ▼
            ┌─────────────┐              ┌──────────────┐ ┌──────────┐
            │  Claude AI  │              │   Telegram   │ │ Reports  │
            │  Laporan    │              │   Bot        │ │ .txt/.md │
            │  Investigasi│              │  Notifikasi  │ │          │
            └─────────────┘              └──────────────┘ └──────────┘
```

### Alur Kerja Sistem

```
Attack Simulation (Kali)
        │
        ▼
Windows Target (SSH/RDP/SMB/Web/Privesc)
        │ Windows Event Log
        ▼
Wazuh Agent ──────► Wazuh Manager
                          │
                    alerts.json
                          │
                    Crontab (tiap 5 menit)
                          │
                    soc_runner.py
                    ├── Triage & Severity Scoring
                    ├── Auto-Block (Active Response)
                    ├── Claude AI → Laporan Investigasi
                    ├── Telegram → Notifikasi
                    └── File → Reports
```

---

## ✨ Fitur Utama

### 🔍 Deteksi Multi-Attack Otomatis
- Monitoring alert Wazuh tiap 5 menit via crontab
- Mendeteksi 5 jenis serangan sekaligus
- Skip otomatis jika tidak ada alert baru (anti-spam)

### ⚡ Auto Response
- Block IP attacker otomatis via **Wazuh Active Response**
- Timeout 600 detik, trigger untuk severity HIGH dan CRITICAL

### 📊 Severity Scoring
| Level | Kondisi |
|-------|---------|
| 🔴 CRITICAL | ≥ 10 percobaan ATAU account locked out |
| 🟠 HIGH | ≥ 5 percobaan |
| 🟡 MEDIUM | < 5 percobaan |

### 🤖 AI Investigation Report
- Integrasi **Claude AI (Anthropic)** untuk analisis mendalam
- Laporan mencakup Executive Summary, Detail Insiden, MITRE ATT&CK Mapping, Rekomendasi
- Output format Markdown profesional

### 📱 Notifikasi Telegram Real-time
- Notifikasi otomatis ke Telegram Bot saat serangan terdeteksi
- Ringkasan lengkap per jenis serangan

### 🖥️ Dashboard Web 6 Tab Real-time
- Auto-refresh tiap 30 detik
- 6 tab: SSH | Web | Privesc | SMB | RDP | Recent Alerts
- Attack timeline chart, IP analysis table, severity badges

---

## 🎯 Attack Coverage

| Fase | Jenis Serangan | Tool | Protocol | Rule ID |
|------|---------------|------|----------|---------|
| Fase 2 | SSH Brute Force | Hydra | SSH/22 | 60122, 60115 |
| Fase 5 | Web App Attack | sqlmap, curl | HTTP/80 | 31103, 31104, 31105 |
| Fase 6 | Privilege Escalation | Sysmon | Windows Events | 61618, 61634, 61638 |
| Fase 7 | SMB Attack | CrackMapExec | SMB/445 | 92652, 60104 |
| Fase 8 | RDP Brute Force | Hydra/Crowbar | RDP/3389 | 60122 (type 3) |

### MITRE ATT&CK Coverage

| Taktik | Teknik | ID |
|--------|--------|-----|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Initial Access | Valid Accounts | T1078 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Lateral Movement | Remote Services: RDP | T1021.001 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |
| Privilege Escalation | Abuse Elevation Control | T1548 |
| Defense Evasion | Impair Defenses | T1562 |
| Discovery | Account Discovery | T1087 |
| Initial Access | Exploit Public-Facing App | T1190 |

---

## 🛠️ Tech Stack

| Komponen | Teknologi |
|----------|-----------|
| SIEM | Wazuh 4.7.5 (Manager + Indexer + Dashboard) |
| Target OS | Windows 11 + Wazuh Agent v4.7.0 |
| Process Monitor | Sysmon v15.15 |
| Web Target | XAMPP + DVWA (PHP 8.x) |
| Attacker | Kali Linux + Hydra + sqlmap + CrackMapExec + Crowbar |
| Language | Python 3.12 |
| Web Framework | Flask |
| AI | Claude AI (Anthropic API) |
| Notification | Telegram Bot API |
| Virtualization | VirtualBox |
| Scheduler | Crontab |

---

## 📁 Struktur Project

```
soc-project/
├── soc_runner.py          # Script utama all-in-one
├── alert_fetcher.py       # Triage standalone
├── ai_investigator.py     # AI investigation standalone
├── dashboard.py           # Dashboard web Flask (6 tab)
├── run_soc.sh             # Wrapper crontab
├── README.md
├── .gitignore
├── reports/
│   ├── alert_*.txt        # Laporan alert
│   └── ai_report_*.md     # Laporan investigasi AI
└── logs/
    ├── cron.log
    └── last_count.txt
```

---

## ⚙️ Setup & Instalasi

### Prerequisites
- VirtualBox
- 3 VM: Lubuntu (Wazuh Server), Windows 11, Kali Linux
- Semua VM dalam satu network (Bridge Adapter)

### 1. Install Wazuh Server (Lubuntu)

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
bash wazuh-install.sh -a
```

Set static IP:
```bash
sudo nano /etc/netplan/50-cloud-init.yaml
sudo netplan apply
```

### 2. Install Wazuh Agent (Windows)

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi `
  -OutFile wazuh-agent.msi
msiexec /i wazuh-agent.msi WAZUH_MANAGER="192.168.1.10" /q
NET START WazuhSvc
```

### 3. Install Sysmon (Windows)

```powershell
New-Item -ItemType Directory -Path "C:\Tools" -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"
.\Sysmon64.exe -accepteula -i
```

### 4. Setup Python Environment

```bash
cd /home/wazuh/soc-project
python3 -m venv .
source bin/activate
pip install requests flask anthropic

echo 'export ANTHROPIC_API_KEY="your-key"' >> bin/activate
echo 'export TELEGRAM_BOT_TOKEN="your-token"' >> bin/activate
echo 'export TELEGRAM_CHAT_ID="your-id"' >> bin/activate
source bin/activate
```

### 5. Konfigurasi Wazuh Active Response

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>60122,60115,31103,31105,92652</rules_id>
  <timeout>600</timeout>
</active-response>
```

### 6. Setup Crontab

```bash
chmod +x run_soc.sh
crontab -e
# */5 * * * * /home/wazuh/soc-project/run_soc.sh

# Sudoers
sudo visudo
# wazuh ALL=(ALL) NOPASSWD: /usr/bin/grep
```

---

## 🚀 Cara Penggunaan

```bash
# Aktifkan venv
cd /home/wazuh/soc-project && source bin/activate

# Jalankan all-in-one
python3 soc_runner.py

# Dashboard web
python3 dashboard.py
# Buka: http://192.168.1.10:5000

# Monitor cron
tail -f logs/cron.log
```

### Simulasi Serangan dari Kali

```bash
# SSH Brute Force
hydra -l wazuh -P pass.txt ssh://192.168.1.11 -t 4 -V

# Web Attack (DVWA)
bash ~/dvwa_attack.sh

# SMB Attack
crackmapexec smb 192.168.1.11 -u attacker -p 'Password123!' --shares

# RDP Brute Force
hydra -l attacker -P pass.txt rdp://192.168.1.11 -t 1 -V
```

---

## 📸 Dashboard

Dashboard web real-time dengan 6 tab di `http://192.168.1.10:5000`

| Tab | Konten |
|-----|--------|
| 🔐 SSH Brute Force | Attempts, timeline, IP table |
| 🌐 Web Attacks | SQLi, XSS, LFI detection |
| ⚡ Privilege Escalation | Sysmon events, suspicious processes |
| 🗂 SMB Attack | Anonymous access, share enumeration |
| 🖥 RDP Brute Force | RDP attempts, timeline |
| 🕐 Recent Alerts | All alert types real-time |

---

## 📈 Hasil & Temuan

| Metrik | Hasil |
|--------|-------|
| Jenis serangan terdeteksi | 5 |
| Total alerts diproses | 400+ |
| Auto-block berhasil | ✅ |
| Anonymous SMB access | Terdeteksi (ADMIN$, C$) |
| RDP attempts | 133+ |
| AI report dengan MITRE ATT&CK | ✅ |
| Telegram notifikasi | Real-time |

### Rule ID yang Dipantau

| Rule ID | Jenis |
|---------|-------|
| 60122, 60115, 60204 | SSH/RDP brute force |
| 31103, 31104, 31105 | Web attacks (SQLi, XSS) |
| 61618, 61634, 61638, 61138 | Sysmon/Privesc |
| 92652, 60104, 60205 | SMB |

---

## 📬 Kontak

Dibuat oleh **KaiX** sebagai bagian dari SOC Analyst Portfolio Lab.

- GitHub: [github.com/humanbetired](https://github.com/humanbetired)

---

> *"Security is not a product, but a process."* — Bruce Schneier

---

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![Claude AI](https://img.shields.io/badge/Claude_AI-Anthropic-orange)
![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)
![License](https://img.shields.io/badge/License-MIT-green)

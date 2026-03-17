# 🛡️ SOC Analyst Portfolio Lab

> **Simulasi lingkungan Security Operations Center (SOC) berbasis Wazuh SIEM dengan otomatisasi Python, integrasi Claude AI, dan notifikasi Telegram real-time.**

---

## Daftar Isi

- [Tentang Project](#-tentang-project)
- [Arsitektur Sistem](#-arsitektur-sistem)
- [Fitur Utama](#-fitur-utama)
- [Tech Stack](#-tech-stack)
- [Struktur Project](#-struktur-project)
- [Setup & Instalasi](#-setup--instalasi)
- [Cara Penggunaan](#-cara-penggunaan)
- [Demo](#-demo)
- [Hasil & Temuan](#-hasil--temuan)
- [Kontak](#-kontak)

---

## Tentang Project

Project ini merupakan simulasi lingkungan SOC yang dibangun untuk keperluan portofolio sebagai **SOC Analyst**. Lab ini mensimulasikan skenario nyata serangan brute force SSH terhadap sistem Windows, mendeteksinya menggunakan Wazuh SIEM, lalu merespons secara otomatis menggunakan kombinasi Python, Claude AI, dan Wazuh Active Response.

### Tujuan
- Membangun pemahaman end-to-end tentang alur kerja SOC
- Mensimulasikan serangan nyata (Hydra brute force) dan mendeteksinya
- Mengotomatisasi proses triage, response, dan pelaporan
- Mengintegrasikan AI untuk menghasilkan laporan investigasi profesional

---

## Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                     NETWORK TOPOLOGY                        │
│                   192.168.1.0/24                            │
│                                                             │
│  ┌──────────────┐    SSH Attack    ┌──────────────────────┐ │
│  │  Kali Linux  │ ──────────────► │   Windows 11         │ │
│  │  (Attacker)  │                 │   (Target)           │ │
│  │ 192.168.1.12 │                 │   192.168.1.11       │ │
│  └──────────────┘                 │   Wazuh Agent v4.7.0 │ │
│                                   └──────────┬───────────┘ │
│                                              │ Log Events   │
│                                              ▼             │
│                                   ┌──────────────────────┐ │
│                                   │   Lubuntu Server     │ │
│                                   │   192.168.1.10       │ │
│                                   │                      │ │
│                                   │  ┌────────────────┐  │ │
│                                   │  │  Wazuh SIEM    │  │ │
│                                   │  │  Manager       │  │ │
│                                   │  │  Indexer       │  │ │
│                                   │  │  Dashboard     │  │ │
│                                   │  └───────┬────────┘  │ │
│                                   │          │            │ │
│                                   │  ┌───────▼────────┐  │ │
│                                   │  │  Python SOC    │  │ │
│                                   │  │  Automation    │  │ │
│                                   │  │  soc_runner.py │  │ │
│                                   │  └───────┬────────┘  │ │
│                                   └──────────┼───────────┘ │
└──────────────────────────────────────────────┼─────────────┘
                                               │
                    ┌──────────────────────────┼──────────────┐
                    │                          │              │
                    ▼                          ▼              ▼
            ┌─────────────┐          ┌──────────────┐  ┌───────────┐
            │  Claude AI  │          │   Telegram   │  │  Reports  │
            │  (Anthropic)│          │    Bot       │  │  .txt/.md │
            │  Laporan    │          │  Notifikasi  │  │  Lokal    │
            │  Investigasi│          │  Real-time   │  │           │
            └─────────────┘          └──────────────┘  └───────────┘
```

### Alur Kerja Sistem

```
Hydra Brute Force
      │
      ▼
Windows SSH (Port 22)
      │ Event 4625 (Logon Failure)
      ▼
Wazuh Agent ──────► Wazuh Manager
                          │
                          │ Rule 60122 (Logon Failure)
                          │ Rule 60115 (Account Lockout)
                          ▼
                    alerts.json
                          │
                    ┌─────▼──────┐
                    │  Crontab   │ (tiap 5 menit)
                    │  run_soc.sh│
                    └─────┬──────┘
                          │ Alert baru?
                          ▼
                    soc_runner.py
                    ┌─────┴──────────────────────┐
                    │                            │
                    ▼                            ▼
             Triage & Scoring           Auto-Block IP
             (CRITICAL/HIGH/           (Wazuh Active
              MEDIUM)                   Response)
                    │
                    ├──► Claude AI ──► Laporan Investigasi
                    │                 (MITRE ATT&CK)
                    │
                    ├──► Telegram ──► Notifikasi Real-time
                    │
                    └──► File ──────► alert_*.txt
                                      ai_report_*.md
```

---

## Fitur Utama

### 1. Deteksi Otomatis
- Monitoring alert Wazuh tiap 5 menit via crontab
- Deteksi brute force SSH berdasarkan rule ID Windows (`60122`, `60115`)
- Skip otomatis jika tidak ada alert baru (anti-spam)

### 2. Auto Response
- Block IP attacker otomatis via **Wazuh Active Response** (`firewall-drop`, timeout 600 detik)
- Trigger hanya untuk severity HIGH dan CRITICAL

### 3. Severity Scoring
| Level | Kondisi |
|-------|---------|
| 🔴 CRITICAL | ≥ 10 percobaan ATAU account locked out |
| 🟠 HIGH | ≥ 5 percobaan |
| 🟡 MEDIUM | < 5 percobaan |

### 4. AI Investigation Report
- Integrasi **Claude AI (Anthropic)** untuk analisis mendalam
- Laporan mencakup: Executive Summary, Detail Insiden, MITRE ATT&CK Mapping, Rekomendasi
- Output dalam format Markdown profesional

### 5. Notifikasi Telegram Real-time
- Notifikasi otomatis ke Telegram Bot saat ada serangan terdeteksi
- Ringkasan: Source IP, Attempts, Severity, Status lockout, Action yang diambil

### 6. Dashboard Web Real-time
- Dashboard berbasis **Flask** dengan auto-refresh tiap 30 detik
- Menampilkan: Summary cards, Attack timeline chart, IP analysis table, Recent alerts
- Akses via browser: `http://192.168.1.10:5000`

---

## Tech Stack

| Komponen | Teknologi |
|----------|-----------|
| SIEM | Wazuh 4.7.5 (Manager + Indexer + Dashboard) |
| Target OS | Windows 11 + Wazuh Agent |
| Attacker | Kali Linux + Hydra |
| Bahasa | Python 3.12 |
| Web Framework | Flask |
| AI | Claude AI (Anthropic API) |
| Notifikasi | Telegram Bot API |
| Virtualisasi | VirtualBox |
| Scheduler | Crontab |

---

## Struktur Project

```
soc-project/
├── soc_runner.py          # Script utama all-in-one
├── alert_fetcher.py       # Triage & severity scoring standalone
├── ai_investigator.py     # AI investigation standalone
├── dashboard.py           # Dashboard web Flask
├── run_soc.sh             # Wrapper script untuk crontab
├── reports/
│   ├── alert_*.txt        # Laporan alert otomatis
│   └── ai_report_*.md     # Laporan investigasi AI
└── logs/
    ├── cron.log           # Log eksekusi cron
    └── last_count.txt     # Counter alert terakhir
```

---

## Setup & Instalasi

### Prerequisites
- VirtualBox
- 3 VM: Lubuntu (Wazuh Server), Windows 11, Kali Linux
- Semua VM dalam satu network (Bridge Adapter)

### 1. Install Wazuh Server (Lubuntu)

```bash
# Download dan jalankan installer Wazuh all-in-one
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
# Edit config.yml sesuai IP server
bash wazuh-install.sh -a
```

### 2. Install Wazuh Agent (Windows)

```powershell
# Download dan install via PowerShell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi `
  -OutFile wazuh-agent.msi
msiexec /i wazuh-agent.msi WAZUH_MANAGER="192.168.1.10" /q
NET START WazuhSvc
```

### 3. Setup Python Environment

```bash
# Clone/buat project directory
mkdir -p /home/wazuh/soc-project
cd /home/wazuh/soc-project

# Buat virtual environment
python3 -m venv .
source bin/activate

# Install dependencies
pip install requests flask anthropic
```

### 4. Konfigurasi Environment Variables

```bash
# Tambahkan ke venv activate
echo 'export ANTHROPIC_API_KEY="your-api-key"' >> bin/activate
echo 'export TELEGRAM_BOT_TOKEN="your-bot-token"' >> bin/activate
echo 'export TELEGRAM_CHAT_ID="your-chat-id"' >> bin/activate
source bin/activate
```

### 5. Setup Crontab

```bash
# Beri permission
chmod +x run_soc.sh

# Daftarkan ke crontab (tiap 5 menit)
crontab -e
# Tambahkan:
# */5 * * * * /home/wazuh/soc-project/run_soc.sh
```

### 6. Konfigurasi Wazuh Active Response

Tambahkan ke `/var/ossec/etc/ossec.conf`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>60122,60115</rules_id>
  <timeout>600</timeout>
</active-response>
```

```bash
sudo systemctl restart wazuh-manager
```

---

## Cara Penggunaan

### Jalankan All-in-One Script

```bash
cd /home/wazuh/soc-project
source bin/activate
python3 soc_runner.py
```

### Jalankan Dashboard Web

```bash
python3 dashboard.py
# Buka browser: http://192.168.1.10:5000
```

### Simulasi Serangan (dari Kali Linux)

```bash
hydra -l wazuh -P pass.txt ssh://192.168.1.11 -t 4 -V
```

### Monitor Log Cron

```bash
tail -f /home/wazuh/soc-project/logs/cron.log
```

---

## Demo

### Dashboard Web Real-time
> Screenshot dashboard menampilkan summary cards, attack timeline, dan IP analysis table.
> <img width="2841" height="1560" alt="image" src="https://github.com/user-attachments/assets/59efd442-ff11-4a90-8908-767fa477836b" />


### Notifikasi Telegram
> Notifikasi otomatis masuk ke Telegram saat serangan terdeteksi.
> ![WhatsApp Image 2026-03-17 at 11 58 54](https://github.com/user-attachments/assets/162ba56a-a006-4e73-a760-2285b893b9f4)


### Sample AI Investigation Report

```
# LAPORAN INVESTIGASI INSIDEN KEAMANAN SIBER

Nomor Tiket : SOC-INC-2026-0316-001
Klasifikasi : CRITICAL
Tanggal     : 16 Maret 2026

## 1. EXECUTIVE SUMMARY
Sistem Wazuh SIEM mendeteksi aktivitas brute force SSH dari IP
192.168.1.12 dengan 39 percobaan login gagal selama 51 menit.
Account target berhasil dikunci otomatis.

## 3. MITRE ATT&CK MAPPING
- T1110.001 — Brute Force: Password Guessing
- T1021.004 — Remote Services: SSH
- T1562.001 — Impair Defenses
...
```

---

## Hasil & Temuan

Selama lab berlangsung, sistem berhasil:

- Mendeteksi **146+ percobaan** brute force SSH dalam multiple sesi
- Mengidentifikasi **1 unique attacker IP** (192.168.1.12)
- Melakukan **auto-block** via Wazuh Active Response dalam hitungan detik
- Menghasilkan laporan investigasi AI dengan **MITRE ATT&CK mapping** otomatis
- Mengirim **notifikasi Telegram real-time** setiap ada serangan baru
- Menjalankan monitoring otomatis tiap **5 menit** via crontab tanpa intervensi manual

### Rule Windows yang Dipantau

| Rule ID | Deskripsi | Severity Wazuh |
|---------|-----------|----------------|
| 60122 | Logon failure - Unknown user or bad password | Level 5 |
| 60115 | User account locked out | Level 10 |
| 60106 | Windows logon success | Level 3 |

---

## Kontak

Dibuat oleh **saya sendiri** sebagai bagian dari SOC Analyst Portfolio Lab.

- GitHub: [github.com/username](https://github.com/humanbetired)
- LinkedIn: [linkedin.com/in/username](https://linkedin.com/in/<soon>)

---

> *"Security is not a product, but a process."* — Bruce Schneier

---

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue?logo=wazuh)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![Claude AI](https://img.shields.io/badge/Claude_AI-Anthropic-orange)
![License](https://img.shields.io/badge/License-MIT-green)

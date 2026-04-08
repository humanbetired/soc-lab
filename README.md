# SOC Analyst Portfolio Lab

> Simulated Security Operations Center (SOC) environment built on Wazuh SIEM with Python automation, Claude AI integration, real-time web dashboard, and Telegram notifications — covering 9 attack scenarios across two lab series.

---

## Table of Contents

- [About](#about)
- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Attack Coverage](#attack-coverage)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Dashboard](#dashboard)
- [Results & Findings](#results--findings)
- [Contact](#contact)

---

## About

This project is a self-built SOC simulation environment constructed for portfolio purposes as a **SOC Analyst**. The lab simulates real-world attack scenarios, detects them using Wazuh SIEM, and responds automatically using a combination of Python, Claude AI, Wazuh Active Response, and Telegram Bot.

The project is divided into two lab series:

**Lab 1 — SOC Analyst Portfolio Lab**: Covers network-based attacks including SSH/RDP brute force, web application attacks, privilege escalation, and SMB enumeration with full automation and dashboard.

**Lab 2 — Malware Simulation Lab**: Extends the environment with endpoint malware simulation covering ransomware, reverse shell, keylogger, and cryptominer — each with a 4-phase Prevention, Detection, Response, and Recovery workflow.

### Objectives
- Build end-to-end understanding of SOC analyst workflows
- Simulate 9 distinct attack scenarios and detect them using Wazuh
- Automate triage, response, and incident reporting
- Integrate AI to generate professional investigation reports
- Implement MITRE ATT&CK-mapped detection rules across all scenarios

---

## System Architecture

```
NETWORK TOPOLOGY — 192.168.1.0/24

  Kali Linux (Attacker)         Windows 11 (Target)
  192.168.1.12          ──────► 192.168.1.11
  Multiple attack tools          Wazuh Agent
                                 XAMPP + DVWA
                                 Sysmon v15.15
                                       |
                                       v
                            Lubuntu Server
                            192.168.1.10
                            Wazuh SIEM 4.7.5
                            Python Automation
                            Flask Dashboard
                                       |
                    -------------------+-------------------
                    |                  |                  |
                    v                  v                  v
              Claude AI           Telegram Bot        Reports
              Investigation       Notifications       .txt / .md
              Reports
```

### System Workflow

```
Attack Simulation (Kali / Windows)
        |
        v
Windows Target — Windows Event Log / Sysmon / FIM
        |
        v
Wazuh Agent ──────► Wazuh Manager
                          |
                    alerts.json
                          |
                    Crontab (every 5 minutes)
                          |
                    soc_runner.py
                    |── Triage & Severity Scoring
                    |── Auto-Block (Active Response)
                    |── Claude AI → Investigation Report
                    |── Telegram → Real-time Notification
                    └── File → Reports
```

---

## Key Features

### Multi-Attack Automated Detection
- Wazuh alert monitoring every 5 minutes via crontab
- Detects 9 attack types across two lab series
- Auto-skip if no new alerts (anti-spam)

### Automated Active Response
- Automatic IP blocking via Wazuh Active Response (firewall-drop)
- 600-second timeout, triggered on HIGH and CRITICAL severity
- Malware-specific response scripts per attack type

### Severity Scoring

| Level    | Condition                                  |
|----------|--------------------------------------------|
| CRITICAL | 10+ attempts OR account locked out         |
| HIGH     | 5+ attempts                                |
| MEDIUM   | Less than 5 attempts                       |

### AI Investigation Report
- Claude AI (Anthropic API) integration for in-depth analysis
- Report covers Executive Summary, Incident Detail, MITRE ATT&CK Mapping, Recommendations
- Professional Markdown output format

### Real-time Telegram Notifications
- Automatic Telegram Bot notifications on attack detection
- Complete summary per attack type with severity and timestamp

### 6-Tab Real-time Web Dashboard
- Auto-refresh every 30 seconds
- Tabs: SSH | Web | Privesc | SMB | RDP | Recent Alerts
- Attack timeline chart, IP analysis table, severity badges

### 4-Phase Malware Response Workflow
Each malware scenario follows: Prevention → Detection → Response → Recovery

---

## Attack Coverage

### Lab 1 — SOC Analyst Portfolio Lab

| Phase | Attack Type           | Tool             | Protocol  | Rule ID                    |
|-------|-----------------------|------------------|-----------|----------------------------|
| 2     | SSH Brute Force       | Hydra            | SSH/22    | 60122, 60115               |
| 5     | Web App Attack        | sqlmap, curl     | HTTP/80   | 31103, 31104, 31105        |
| 6     | Privilege Escalation  | Sysmon           | Win Events| 61618, 61634, 61638        |
| 7     | SMB Attack            | CrackMapExec     | SMB/445   | 92652, 60104               |
| 8     | RDP Brute Force       | Hydra/Crowbar    | RDP/3389  | 60122 (logon type 3)       |

### Lab 2 — Malware Simulation Lab

| Scenario | Attack Type    | Method                        | Rule ID | MITRE        |
|----------|----------------|-------------------------------|---------|--------------|
| 1        | Ransomware     | XOR encryption + FIM trigger  | 100201  | T1486        |
| 2        | Reverse Shell  | msfvenom + Meterpreter        | 100211  | T1059        |
| 3        | Keylogger      | Python pynput                 | 100220  | T1056.001    |
| 4        | Cryptominer    | Python CPU stress simulation  | 100231  | T1496        |

### MITRE ATT&CK Coverage

| Tactic              | Technique                          | ID         |
|---------------------|------------------------------------|------------|
| Credential Access   | Brute Force: Password Guessing     | T1110.001  |
| Credential Access   | Brute Force: Password Spraying     | T1110.003  |
| Initial Access      | Valid Accounts                     | T1078      |
| Initial Access      | Exploit Public-Facing Application  | T1190      |
| Lateral Movement    | Remote Services: SSH               | T1021.004  |
| Lateral Movement    | Remote Services: RDP               | T1021.001  |
| Lateral Movement    | SMB/Windows Admin Shares           | T1021.002  |
| Privilege Escalation| Abuse Elevation Control Mechanism  | T1548      |
| Defense Evasion     | Impair Defenses                    | T1562      |
| Discovery           | Account Discovery                  | T1087      |
| Impact              | Data Encrypted for Impact          | T1486      |
| Execution           | Command and Scripting Interpreter  | T1059      |
| Collection          | Input Capture: Keylogging          | T1056.001  |
| Resource Development| Resource Hijacking                 | T1496      |

---

## Screenshots

### Infrastructure & SIEM

<!-- Screenshot: Wazuh Dashboard overview showing active agents and alert summary -->
<img width="2879" height="1555" alt="image" src="https://github.com/user-attachments/assets/13c57ad3-c6c2-47b0-8491-84fbf68ded4a"/>

<!-- Screenshot: Three VM setup in VirtualBox — Lubuntu server, Windows target, Kali attacker -->
<img width="2879" height="1798" alt="image" src="https://github.com/user-attachments/assets/96f4b372-e7f8-483b-acb2-6ff8747b17f9" />
<img width="1365" height="720" alt="image" src="https://github.com/user-attachments/assets/3877d4b7-3ff3-43b7-add2-e6aa5b737d13" />


### Lab 1 — Attack Detection
<img width="1220" height="2712" alt="image" src="https://github.com/user-attachments/assets/fb2b2dac-48de-4893-a676-c7f619382996" />

### Lab 2 — Malware Simulation
<img width="1220" height="2712" alt="image" src="https://github.com/user-attachments/assets/32f76954-7594-4049-a9ba-8ae391c536de" />
<img width="1220" height="2712" alt="image" src="https://github.com/user-attachments/assets/20e65773-230d-4ee7-be6e-3b24870f3f79" />

### Automation & Response

<!-- Screenshot: Flask dashboard showing all 6 tabs with real-time alert data -->
<img width="2879" height="1554" alt="image" src="https://github.com/user-attachments/assets/2e03fdb8-6859-4182-80e0-26f2fb7d7ec8" />


---

## Tech Stack

| Component          | Technology                                      |
|--------------------|-------------------------------------------------|
| SIEM               | Wazuh 4.7.5 (Manager + Indexer + Dashboard)     |
| Target OS          | Windows 11 + Wazuh Agent v4.7.0                 |
| Process Monitor    | Sysmon v15.15                                   |
| Web Target         | XAMPP + DVWA (PHP 8.x)                          |
| Attacker           | Kali Linux + Hydra + sqlmap + CrackMapExec      |
| Language           | Python 3.12                                     |
| Web Framework      | Flask                                           |
| AI                 | Claude AI (Anthropic API)                       |
| Notification       | Telegram Bot API                                |
| Virtualization     | VirtualBox                                      |
| Scheduler          | Crontab                                         |

---

## Project Structure

```
soc-project/
|── soc_runner.py              # Main all-in-one script
|── alert_fetcher.py           # Standalone triage
|── ai_investigator.py         # Standalone AI investigation
|── dashboard.py               # Flask web dashboard (6 tabs)
|── run_soc.sh                 # Crontab wrapper
|── README.md
|── .gitignore
|── malware-lab/
|   |── ransomware_sim.py      # Ransomware simulation
|   |── decrypt_sim.py         # Recovery script
|   |── keylogger_sim.py       # Keylogger simulation
|   |── cryptominer_sim.py     # Cryptominer simulation
|   |── recovery_keylogger.ps1 # Keylogger recovery
|   |── recovery_miner.ps1     # Miner recovery
|   └── recovery_reverseshell.ps1
|── active-response/
    |── kill-ransomware.sh
    |── kill-keylogger.sh
    |── kill-miner.sh
    └── kill-reverseshell.sh
```

---

## Setup & Installation

### Prerequisites
- VirtualBox
- 3 VMs: Lubuntu (Wazuh Server), Windows 11, Kali Linux
- All VMs on the same network (Bridge Adapter)

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

### 5. Configure Wazuh Active Response

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

# Sudoers — passwordless grep for alert monitoring
sudo visudo
# wazuh ALL=(ALL) NOPASSWD: /usr/bin/grep
```

---

## Usage

```bash
# Activate virtual environment
cd /home/wazuh/soc-project && source bin/activate

# Run all-in-one SOC runner
python3 soc_runner.py

# Launch web dashboard
python3 dashboard.py
# Open: http://192.168.1.10:5000

# Monitor cron logs
tail -f logs/cron.log
```

### Attack Simulation from Kali

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

### Malware Simulation from Windows

```powershell
# Ransomware simulation
python ransomware_sim.py

# Keylogger simulation
python keylogger_sim.py

# Cryptominer simulation
python cryptominer_sim.py
```

---

## Dashboard

Real-time web dashboard with 6 tabs at `http://192.168.1.10:5000`

| Tab              | Content                                       |
|------------------|-----------------------------------------------|
| SSH Brute Force  | Attempt count, timeline chart, IP table       |
| Web Attacks      | SQLi, XSS, LFI detection with rule mapping    |
| Privilege Escal. | Sysmon events, suspicious process list        |
| SMB Attack       | Anonymous access, share enumeration events    |
| RDP Brute Force  | RDP attempt count, timeline                   |
| Recent Alerts    | All alert types in real-time                  |

---

## Results & Findings

### Lab 1 — SOC Portfolio Lab

| Metric                        | Result         |
|-------------------------------|----------------|
| Attack types detected         | 5              |
| Total alerts processed        | 400+           |
| Auto-block executed           | Successful     |
| Anonymous SMB access detected | Yes (ADMIN$, C$)|
| RDP attempts logged           | 133+           |
| AI report with MITRE ATT&CK   | Generated      |
| Telegram notifications        | Real-time      |

### Lab 2 — Malware Simulation Lab

| Scenario       | Detection Method         | Active Response     | Recovery     |
|----------------|--------------------------|---------------------|--------------|
| Ransomware     | FIM + rule 100201        | kill-ransomware.sh  | decrypt_sim.py|
| Reverse Shell  | Sysmon EID 3 + rule 100211| kill-reverseshell.sh| Payload removal|
| Keylogger      | FIM + rule 100220        | kill-keylogger.sh   | recovery_keylogger.ps1|
| Cryptominer    | Process name + rule 100231| kill-miner.sh      | recovery_miner.ps1|

### Custom Rule IDs Deployed

| Rule ID        | Attack Type                        |
|----------------|------------------------------------|
| 60122, 60115   | SSH / RDP brute force              |
| 31103-31105    | Web attacks (SQLi, XSS)            |
| 61618, 61634   | Sysmon / Privilege escalation      |
| 92652, 60104   | SMB enumeration                    |
| 100201         | Ransomware (FIM + encrypted file)  |
| 100211         | Reverse shell (NetworkConnect)     |
| 100220         | Keylogger (file artifact)          |
| 100230, 100231 | Cryptominer (process detection)    |

---

## Contact

Built by **Haryo Prastiko** as part of a self-directed SOC Analyst Portfolio.

- GitHub: [github.com/humanbetired](https://github.com/humanbetired)
- LinkedIn: [linkedin.com/in/haryoprastiko](https://linkedin.com/in/haryoprastiko)
- Medium: [medium.com/@vernanda089](https://medium.com/@vernanda089)

---

> "Security is not a product, but a process." — Bruce Schneier

---

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![Claude AI](https://img.shields.io/badge/Claude_AI-Anthropic-orange)
![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)
![License](https://img.shields.io/badge/License-MIT-green)

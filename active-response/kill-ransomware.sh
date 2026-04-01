#!/bin/bash

# ── Wazuh Active Response: Kill Ransomware + Telegram Alert ──
TELEGRAM_BOT_TOKEN="8726881346:AAF_n5FoQEvSKQvy8Hdvr2CZzsMQrVX91kM"
TELEGRAM_CHAT_ID="1230688086"
LOG="/var/ossec/logs/active-responses.log"

echo "$(date) - [RANSOMWARE RESPONSE] Active response triggered" >> $LOG

# Kirim Telegram alert
MESSAGE="🚨 *RANSOMWARE DETECTED!*

*Agent*: Windows-Target (192.168.1.11)
*Rule*: 100201 - Encrypted file extension detected
*MITRE*: T1486 - Data Encrypted for Impact
*Action*: Active Response triggered
*Time*: $(date)

⚠️ File enkripsi massal terdeteksi di C:\\Users\\iamus\\Documents"

curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d parse_mode="Markdown" \
    -d text="${MESSAGE}" >> $LOG 2>&1

echo "$(date) - [RANSOMWARE RESPONSE] Telegram alert sent" >> $LOG

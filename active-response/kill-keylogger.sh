#!/bin/bash
# Kill keylogger process via SSH ke Windows agent
LOCAL=$(hostname)
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
LOG="/var/ossec/logs/active-responses.log"

echo "$TIMESTAMP - kill-keylogger triggered on $LOCAL" >> $LOG

# Kirim Telegram notif
BOT_TOKEN="8726881346:AAF_n5FoQEvSKQvy8Hdvr2CZzsMQrVX91kM"
CHAT_ID="1230688086"
MSG="🚨 KEYLOGGER DETECTED%0A⏰ $TIMESTAMP%0A🖥️ Windows-Target (192.168.1.11)%0A📁 File keylog_output.txt muncul di Documents%0A🔴 MITRE T1056.001 - Keylogging"

curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" \
    -d "text=${MSG}" >> $LOG 2>&1

echo "$TIMESTAMP - Telegram notif sent" >> $LOG

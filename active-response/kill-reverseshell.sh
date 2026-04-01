#!/bin/bash
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
LOG="/var/ossec/logs/active-responses.log"

echo "$TIMESTAMP - kill-reverseshell triggered" >> $LOG

BOT_TOKEN="8726881346:AAF_n5FoQEvSKQvy8Hdvr2CZzsMQrVX91kM"
CHAT_ID="1230688086"
MSG="🚨 REVERSE SHELL DETECTED%0A⏰ $TIMESTAMP%0A🖥️ Windows-Target (192.168.1.11)%0A🔗 Outbound connection ke 192.168.1.12:4444%0A🔴 MITRE T1059 - Command and Scripting Interpreter"

curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" \
    -d "text=${MSG}" >> $LOG 2>&1

echo "$TIMESTAMP - Telegram notif sent" >> $LOG

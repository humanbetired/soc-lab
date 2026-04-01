#!/bin/bash

LOG=/home/wazuh/soc-project/logs/cron.log
LOCKFILE=/home/wazuh/soc-project/logs/last_count.txt

# Load venv
source /home/wazuh/soc-project/bin/activate

# Hitung alert saat ini — pastikan output bersih integer
CURRENT=$(sudo grep -cE '"id":"60122"|"id":"60115"' /var/ossec/logs/alerts/alerts.json 2>/dev/null)
CURRENT=${CURRENT:-0}
CURRENT=$(echo $CURRENT | tr -d '[:space:]')

# Baca jumlah alert terakhir
LAST=$(cat $LOCKFILE 2>/dev/null)
LAST=${LAST:-0}
LAST=$(echo $LAST | tr -d '[:space:]')

echo "[$(date)] Current: $CURRENT | Last: $LAST" >> $LOG

# Jalankan hanya jika ada alert baru
if [ "$CURRENT" -gt "$LAST" ]; then
    echo "[$(date)] Alert baru ditemukan! Menjalankan soc_runner..." >> $LOG
    python3 /home/wazuh/soc-project/soc_runner.py >> $LOG 2>&1
    echo "$CURRENT" > $LOCKFILE
else
    echo "[$(date)] Tidak ada alert baru, skip." >> $LOG
fi

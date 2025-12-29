#!/bin/bash
#Author: Anthony Kwok
# Detect SSH brute force attempts from logs

LOG_FILE="/var/log/secure"   # RHEL default
ALT_LOG="/var/log/auth.log"  # Debian-based fallback

if [[ -f "$LOG_FILE" ]]; then
  TARGET_LOG="$LOG_FILE"
elif [[ -f "$ALT_LOG" ]]; then
  TARGET_LOG="$ALT_LOG"
else
  echo "[-] No auth log found"
  exit 1
fi

echo "[+] Parsing $TARGET_LOG for failed SSH logins"
grep "Failed password" "$TARGET_LOG" | \
awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

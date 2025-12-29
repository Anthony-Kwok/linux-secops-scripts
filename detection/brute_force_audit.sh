#!/bin/bash
# Author: Anthony Kwok
# Version: 1.01
# Detects password + publickey failures, extracts user + IP safely

LOGS=(
  "/var/log/secure"
  "/var/log/auth.log"
)

TARGET_LOG=""
for log in "${LOGS[@]}"; do
  [[ -f "$log" ]] && TARGET_LOG="$log" && break
done

if [[ -z "$TARGET_LOG" ]]; then
  echo "[-] No SSH authentication log found"
  exit 1
fi

echo "[+] Analyzing SSH auth failures in: $TARGET_LOG"
echo

# Regex notes:
# - Handles "Failed password" and "Failed publickey"
# - Captures:
#   USER (valid or invalid)
#   IP (IPv4 or IPv6)
# - Avoids reliance on fixed field positions

grep -E "sshd.*Failed (password|publickey)" "$TARGET_LOG" | \
awk '
{
  user="UNKNOWN"
  ip="UNKNOWN"

  # Extract user (valid or invalid)
  if (match($0, /for (invalid user )?([^ ]+)/, u)) {
    user=u[2]
  }

  # Extract IPv4 or IPv6 address
  if (match($0, /from ([0-9a-fA-F:.]+)/, i)) {
    ip=i[1]
  }

  if (user != "UNKNOWN" && ip != "UNKNOWN") {
    print ip "|" user
  }
}
' | sort | uniq -c | sort -nr

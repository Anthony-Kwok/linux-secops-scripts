#!/bin/bash
#Author: Anthony Kwok
# Audit common Linux persistence mechanisms

echo "[+] Cron jobs (all users)"
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -u "$user" -l 2>/dev/null | sed "s/^/[$user] /"
done

echo
echo "[+] System-wide cron directories"
ls -la /etc/cron.*

echo
echo "[+] Enabled systemd services"
systemctl list-unit-files --type=service --state=enabled

echo
echo "[+] Recently modified systemd service files (last 7 days)"
find /etc/systemd/system -type f -mtime -7 2>/dev/null

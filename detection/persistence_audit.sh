#!/bin/bash
# Author: Anthony Kwok
# Version: 1.01
# Supports local users + LDAP/AD (via NSS)

set -o errexit
set -o pipefail

echo "[+] Starting persistence audit"
echo

############################################
# USER ENUMERATION (LOCAL + LDAP/AD)
############################################

echo "[+] Enumerating users via NSS (local + LDAP/AD)"
USERS=$(getent passwd | awk -F: '$3 >= 1000 {print $1}')

############################################
# CRON JOBS (ALL USERS)
############################################

echo
echo "[+] User cron jobs"
for user in $USERS; do
  crontab -u "$user" -l 2>/dev/null | sed "s/^/[cron][$user] /"
done

############################################
# SYSTEM-WIDE CRON
############################################

echo
echo "[+] System-wide cron directories"
for dir in /etc/cron.*; do
  [[ -d "$dir" ]] && ls -la "$dir"
done

############################################
# SYSTEMD SERVICES (SYSTEM)
############################################

echo
echo "[+] Enabled systemd services (system)"
systemctl list-unit-files --type=service --state=enabled

############################################
# SYSTEMD SERVICES (USER LEVEL)
############################################

echo
echo "[+] User-level systemd services (local + LDAP/AD home dirs)"
find /home -type f -path "*/.config/systemd/user/*.service" 2>/dev/null

############################################
# RECENT SYSTEMD MODIFICATIONS
############################################

echo
echo "[+] Recently modified systemd service files (last 7 days)"
find /etc/systemd/system \
     /usr/lib/systemd/system \
     -type f -mtime -7 2>/dev/null

############################################
# INIT / LEGACY PERSISTENCE
############################################

echo
echo "[+] Legacy init persistence"
ls -la /etc/init.d 2>/dev/null

############################################
# SHELL STARTUP PERSISTENCE
############################################

echo
echo "[+] Shell startup persistence files"
for user in $USERS; do
  home=$(getent passwd "$user" | awk -F: '{print $6}')
  [[ -d "$home" ]] || continue

  find "$home" -maxdepth 1 \
    -name ".bashrc" \
    -o -name ".bash_profile" \
    -o -name ".profile" 2>/dev/null \
    | sed "s|^|[shell][$user] |"
done

############################################
# SSH AUTHORIZED KEYS
############################################

echo
echo "[+] SSH authorized_keys (local + LDAP/AD users)"
for user in $USERS; do
  home=$(getent passwd "$user" | awk -F: '{print $6}')
  [[ -f "$home/.ssh/authorized_keys" ]] && \
    ls -la "$home/.ssh/authorized_keys" | sed "s|^|[ssh][$user] |"
done

############################################
# SUSPICIOUS SYSTEMD HEURISTICS
############################################

echo
echo "[+] Suspicious systemd ExecStart patterns"
grep -R "ExecStart=" /etc/systemd/system /usr/lib/systemd/system 2>/dev/null | \
grep -E "(curl|wget|bash|sh|nc|python|/tmp|/dev/shm)"

############################################
# KERNEL MODULE PERSISTENCE
############################################

echo
echo "[+] Loaded kernel modules"
lsmod

############################################
# COMPLETION
############################################

echo
echo "[+] Persistence audit complete"

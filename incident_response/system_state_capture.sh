#!/bin/bash
# High-level system triage snapshot

echo "[+] Hostname and uptime"
hostname
uptime

echo
echo "[+] Logged-in users"
who

echo
echo "[+] Running processes (top 20 by CPU)"
ps aux --sort=-%cpu | head -20

echo
echo "[+] Disk usage"
df -h

echo
echo "[+] Loaded kernel modules"
lsmod

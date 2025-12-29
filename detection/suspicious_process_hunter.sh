#!/bin/bash
#Author Anthony Kwok
# Detect suspicious processes and common LOLBins

echo "[+] Processes running from suspicious directories"
ps -eo pid,ppid,user,cmd | grep -E "/tmp|/dev/shm|/var/tmp" | grep -v grep

echo
echo "[+] Common LOLBins used for abuse"
ps -eo pid,user,cmd | grep -E "curl|wget|nc|ncat|bash -i|python -c|perl -e" | grep -v grep

echo
echo "[+] Processes without a TTY (possible background malware)"
ps -eo pid,tty,user,cmd | awk '$2=="?" {print}'

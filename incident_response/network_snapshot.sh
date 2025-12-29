#!/bin/bash
# Capture active network state for incident response

echo "[+] Listening ports"
ss -tulnp

echo
echo "[+] Established outbound connections"
ss -antp | grep ESTAB

echo
echo "[+] Top remote IPs by connection count"
ss -ant | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head

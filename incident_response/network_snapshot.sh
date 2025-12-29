#!/bin/bash
# Author: Anthony Kwok
# Version: 1.01
# network state capture script for incident response
# Outputs line-delimited JSON with MITRE ATT&CK tagging for Splunk or other SIEM tool

TIMESTAMP=$(date +%s)
HOSTNAME=$(hostname)

MITRE_TACTIC="Command and Control"
MITRE_TECHNIQUES=("T1071" "T1095" "T1041")

############################################
# FUNCTION: JSON escape
############################################
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

############################################
# LISTENING PORTS
############################################
ss -tulnpH | while read -r proto state recv send local peer pidproc; do
  pid=$(echo "$pidproc" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')
  cmd=$(ps -p "$pid" -o cmd= 2>/dev/null)

  cat <<EOF
{
  "timestamp": $TIMESTAMP,
  "hostname": "$(json_escape "$HOSTNAME")",
  "event_type": "listening_port",
  "protocol": "$(json_escape "$proto")",
  "local_address": "$(json_escape "$local")",
  "process_pid": "$pid",
  "process_cmd": "$(json_escape "$cmd")",
  "mitre_tactic": "$MITRE_TACTIC",
  "mitre_techniques": ["${MITRE_TECHNIQUES[@]}"]
}
EOF
done

############################################
# ESTABLISHED CONNECTIONS
############################################
ss -antpH state established | while read -r proto state recv send local remote pidproc; do
  pid=$(echo "$pidproc" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')
  cmd=$(ps -p "$pid" -o cmd= 2>/dev/null)

  # Extract IPs safely (IPv4 / IPv6)
  local_ip=$(echo "$local" | sed 's/\[//;s/\]//' | awk -F: '{print $1}')
  remote_ip=$(echo "$remote" | sed 's/\[//;s/\]//' | awk -F: '{print $1}')

  direction="outbound"
  if [[ "$local_ip" == "$remote_ip" ]]; then
    direction="loopback"
  fi

  cat <<EOF
{
  "timestamp": $TIMESTAMP,
  "hostname": "$(json_escape "$HOSTNAME")",
  "event_type": "network_connection",
  "state": "ESTABLISHED",
  "direction": "$direction",
  "local_address": "$(json_escape "$local")",
  "remote_address": "$(json_escape "$remote")",
  "remote_ip": "$(json_escape "$remote_ip")",
  "process_pid": "$pid",
  "process_cmd": "$(json_escape "$cmd")",
  "mitre_tactic": "$MITRE_TACTIC",
  "mitre_techniques": ["${MITRE_TECHNIQUES[@]}"]
}
EOF
done

############################################
# TOP REMOTE IPS BY CONNECTION COUNT
############################################
ss -antH | awk '{print $5}' | sed 's/\[//;s/\]//' | awk -F: '{print $1}' \
| sort | uniq -c | sort -nr | head | while read -r count ip; do

  cat <<EOF
{
  "timestamp": $TIMESTAMP,
  "hostname": "$(json_escape "$HOSTNAME")",
  "event_type": "connection_summary",
  "remote_ip": "$(json_escape "$ip")",
  "connection_count": $count,
  "mitre_tactic": "$MITRE_TACTIC",
  "mitre_techniques": ["${MITRE_TECHNIQUES[@]}"]
}
EOF
done

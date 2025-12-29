#!/bin/bash
# Author: Anthony Kwok
# Version: 1.02
# Features:
# - Time window analysis
# - Password + publickey failures
# - User + IP extraction
# - IPv4 + IPv6 support
# - JSON output for SIEM (Splunk)
# - MITRE ATT&CK tagging

TIME_WINDOW_MINUTES=15   # Adjustable IR window
NOW_EPOCH=$(date +%s)
WINDOW_START=$((NOW_EPOCH - TIME_WINDOW_MINUTES * 60))

LOGS=(
  "/var/log/secure"
  "/var/log/auth.log"
)

TARGET_LOG=""
for log in "${LOGS[@]}"; do
  [[ -f "$log" ]] && TARGET_LOG="$log" && break
done

if [[ -z "$TARGET_LOG" ]]; then
  echo '{"error":"No SSH authentication log found"}'
  exit 1
fi

# MITRE ATT&CK context
MITRE_TACTIC="Credential Access"
MITRE_TECHNIQUE="Brute Force"
MITRE_ID="T1110"
MITRE_SUBTECHNIQUE="T1110.001"

grep -E "sshd.*Failed (password|publickey)" "$TARGET_LOG" | \
awk -v window_start="$WINDOW_START" \
    -v mitre_tactic="$MITRE_TACTIC" \
    -v mitre_technique="$MITRE_TECHNIQUE" \
    -v mitre_id="$MITRE_ID" \
    -v mitre_subtechnique="$MITRE_SUBTECHNIQUE" '
{
  # Example syslog date: "Jan 12 14:22:01"
  cmd = "date -d \"" $1 " " $2 " " $3 "\" +%s"
  cmd | getline event_time
  close(cmd)

  if (event_time < window_start) next

  user="UNKNOWN"
  ip="UNKNOWN"
  method="UNKNOWN"

  if (match($0, /Failed password/, m)) method="password"
  if (match($0, /Failed publickey/, m)) method="publickey"

  if (match($0, /for (invalid user )?([^ ]+)/, u)) {
    user=u[2]
  }

  if (match($0, /from ([0-9a-fA-F:.]+)/, i)) {
    ip=i[1]
  }

  if (user != "UNKNOWN" && ip != "UNKNOWN") {
    key=ip "|" user "|" method
    count[key]++
    first_seen[key] = (first_seen[key] == "" || event_time < first_seen[key]) ? event_time : first_seen[key]
    last_seen[key]  = (event_time > last_seen[key]) ? event_time : last_seen[key]
  }
}
END {
  for (k in count) {
    split(k, parts, "|")
    printf "{"
    printf "\"event_type\":\"ssh_auth_failure\","
    printf "\"src_ip\":\"%s\",", parts[1]
    printf "\"user\":\"%s\",", parts[2]
    printf "\"auth_method\":\"%s\",", parts[3]
    printf "\"attempt_count\":%d,", count[k]
    printf "\"first_seen\":%d,", first_seen[k]
    printf "\"last_seen\":%d,", last_seen[k]
    printf "\"time_window_minutes\":%d,", ENVIRON["TIME_WINDOW_MINUTES"]
    printf "\"mitre_tactic\":\"%s\",", mitre_tactic
    printf "\"mitre_technique\":\"%s\",", mitre_technique
    printf "\"mitre_technique_id\":\"%s\",", mitre_id
    printf "\"mitre_subtechnique\":\"%s\"", mitre_subtechnique
    printf "}\n"
  }
}'

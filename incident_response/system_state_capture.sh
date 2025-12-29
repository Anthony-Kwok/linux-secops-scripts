#!/bin/bash
# Author: Anthony Kwok
# Version: 1.01
# system triage snapshot script with JSON output
# MITRE ATT&CK aligned

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)
OS=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)
UPTIME_SEC=$(cut -d. -f1 /proc/uptime)

json_escape() {
  jq -Rs .
}

echo "{"
echo "  \"timestamp\": \"$TIMESTAMP\","
echo "  \"hostname\": \"$HOSTNAME\","
echo "  \"os\": \"$OS\","
echo "  \"kernel\": \"$KERNEL\","
echo "  \"uptime_seconds\": $UPTIME_SEC,"

### Logged-in users (MITRE: T1078 - Valid Accounts)
echo "  \"logged_in_users\": {"
echo "    \"mitre\": { \"technique\": \"T1078\", \"tactic\": \"Initial Access / Persistence\" },"
who --ips 2>/dev/null | \
awk '{print "{\"user\":\""$1"\",\"tty\":\""$2"\",\"source\":\""$5"\",\"login_time\":\""$3" "$4"\"},"}' | \
sed '$ s/,$//' | \
sed '1s/^/    \"sessions\": [/' | sed '$s/$/]/'
echo "  },"

### Running processes (MITRE: T1057 - Process Discovery)
echo "  \"top_processes\": {"
echo "    \"mitre\": { \"technique\": \"T1057\", \"tactic\": \"Discovery\" },"
ps -eo pid,user,comm,%cpu,%mem --sort=-%cpu | head -21 | \
awk 'NR>1 {print "{\"pid\":"$1",\"user\":\""$2"\",\"command\":\""$3"\",\"cpu\":"$4",\"mem\":"$5"},"}' | \
sed '$ s/,$//' | \
sed '1s/^/    \"processes\": [/' | sed '$s/$/]/'
echo "  },"

### Disk usage (MITRE: T1083 - File and Directory Discovery)
echo "  \"disk_usage\": {"
echo "    \"mitre\": { \"technique\": \"T1083\", \"tactic\": \"Discovery\" },"
df -h --output=source,size,used,avail,pcent,target | tail -n +2 | \
awk '{print "{\"filesystem\":\""$1"\",\"size\":\""$2"\",\"used\":\""$3"\",\"available\":\""$4"\",\"usage\":\""$5"\",\"mount\":\""$6"\"},"}' | \
sed '$ s/,$//' | \
sed '1s/^/    \"filesystems\": [/' | sed '$s/$/]/'
echo "  },"

### Loaded kernel modules (MITRE: T1014 - Rootkit)
echo "  \"kernel_modules\": {"
echo "    \"mitre\": { \"technique\": \"T1014\", \"tactic\": \"Defense Evasion\" },"
lsmod | awk 'NR>1 {print "{\"module\":\""$1"\",\"size\":"$2",\"used_by\":\""$3"\"},"}' | \
sed '$ s/,$//' | \
sed '1s/^/    \"modules\": [/' | sed '$s/$/]/'
echo "  }"

echo "}"

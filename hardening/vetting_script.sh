#!/usr/bin/env bash
# Author: Anthony Kwok
# Name: vetting_script.sh
# Purpose: Cross-distro Linux IR snapshot with hardening guidance
# Supports: RHEL 8/9, Debian, Ubuntu
# License: MIT Open Source
# Version: 2.1.0

set -Eeuo pipefail
IFS=$'\n\t'

########################
# Environment & Safety #
########################

DATE=$(date -Is)
HOSTNAME=$(hostname -s)
LOGFILE=$(mktemp /tmp/linux_ir_${HOSTNAME}.XXXXXX.log)

require_root() {
  [[ "$EUID" -eq 0 ]] || {
    echo "ERROR: Must be run as root"
    exit 1
  }
}

have() { command -v "$1" &>/dev/null; }

################
# Output API  #
################

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$LOGFILE"
}

section() {
  log "========== $* =========="
}

finding() {
  local sev="$1" msg="$2" impact="$3" fix="$4"
  log "[FINDING][$sev] $msg"
  log "[IMPACT] $impact"
  log "[HARDENING] $fix"
}

run() {
  log "Running: $*"
  "$@" >>"$LOGFILE" 2>&1 || log "[WARN] Command failed: $*"
  echo >>"$LOGFILE"
}

trim() {
  grep -Ev '^\s*#|^\s*$' "$@" 2>/dev/null || true
}

########################
# Distro Detection     #
########################

detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="$ID"
  else
    DISTRO="unknown"
  fi
  log "Detected distro: $DISTRO"
}

########################
# Metadata             #
########################

metadata() {
  section "System Metadata"
  run hostname
  run uname -a
  run date
  run cat /etc/os-release
}

########################
# Network              #
########################

network_checks() {
  section "Network"

  have ip && run ip addr
  have ss && run ss -tulpn

  if have nft; then
    run nft list ruleset
  elif have iptables; then
    run iptables -S
  else
    finding MEDIUM \
      "No firewall tooling detected" \
      "Host may be fully exposed to the network" \
      "Install and enable nftables (RHEL/Debian) or ufw (Ubuntu)"
  fi
}

########################
# SSH / Auth           #
########################

auth_checks() {
  section "Authentication"

  local sshd_cfg="/etc/ssh/sshd_config"

  run trim "$sshd_cfg"

  if grep -Eq '^PermitRootLogin\s+yes' "$sshd_cfg"; then
    finding HIGH \
      "SSH root login enabled" \
      "Direct remote root access increases compromise impact" \
      "Set PermitRootLogin no in sshd_config and reload sshd"
  fi

  if grep -Eq '^PasswordAuthentication\s+yes' "$sshd_cfg"; then
    finding MEDIUM \
      "SSH password authentication enabled" \
      "Passwords are vulnerable to brute force attacks" \
      "Disable PasswordAuthentication and enforce SSH keys"
  fi

  uid0=$(getent passwd | awk -F: '$3 == 0 {print $1}')
  [[ "$uid0" != "root" ]] && finding HIGH \
    "Non-root UID 0 account(s): $uid0" \
    "Multiple UID 0 accounts bypass privilege separation" \
    "Remove extra UID 0 accounts or change UID to non-zero"
}

########################
# Users & Credentials  #
########################

user_checks() {
  section "Users & Credentials"

  run getent passwd | grep -Ev 'nologin|false|sync'

  local weak_users
  weak_users=$(getent shadow | awk -F: '$2 !~ /^(\*|!|x)$/ {print $1}')
  [[ -n "$weak_users" ]] && finding MEDIUM \
    "Users with local password hashes detected" \
    "Local passwords increase attack surface" \
    "Disable local passwords or enforce centralized auth (LDAP/SSSD)"
}

########################
# Persistence          #
########################

persistence_checks() {
  section "Persistence"

  run trim /etc/crontab
  run ls -l /etc/cron.* || true

  find /etc/systemd/system -type f -name '*.service' 2>/dev/null | \
    grep -q . && finding MEDIUM \
      "Custom systemd services present" \
      "Custom services can be abused for persistence" \
      "Review service files and verify legitimacy"
}

########################
# Filesystem Security  #
########################

filesystem_checks() {
  section "Filesystem Security"

  find / -xdev -perm -4000 -type f 2>/dev/null | \
    grep -Ev '^/(usr|bin|sbin)/' | \
    while read -r f; do
      finding HIGH \
        "Non-standard SUID binary: $f" \
        "SUID binaries can enable privilege escalation" \
        "Remove SUID bit or validate binary legitimacy"
    done

  echo "$PATH" | tr ':' '\n' | while read -r p; do
    [[ -w "$p" ]] && finding MEDIUM \
      "Writable PATH directory: $p" \
      "Writable PATH enables command hijacking" \
      "Remove write permissions from PATH directories"
  done
}

########################
# Runtime State        #
########################

runtime_checks() {
  section "Runtime State"

  run w
  run ps auxf

  if have getenforce; then
    getenforce | grep -q Enforcing || finding HIGH \
      "SELinux not enforcing" \
      "MAC controls are not protecting the system" \
      "Set SELINUX=enforcing and reboot (RHEL)"
  fi

  if have aa-status; then
    aa-status | grep -q enabled || finding MEDIUM \
      "AppArmor not enforcing" \
      "Application confinement is disabled" \
      "Enable AppArmor profiles (Ubuntu/Debian)"
  fi
}

########################
# Logging & Time       #
########################

logging_checks() {
  section "Logging & Time"

  run trim /etc/rsyslog.conf /etc/rsyslog.d/*

  if have chronyc; then
    run chronyc sources
  elif have timedatectl; then
    run timedatectl status
  else
    finding LOW \
      "Time synchronization not verified" \
      "Incorrect time impacts log correlation" \
      "Install and enable chrony or systemd-timesyncd"
  fi
}

########################
# Software Inventory   #
########################

software_inventory() {
  section "Installed Packages"

  if have rpm; then
    run rpm -qa | sort
  elif have dpkg; then
    run dpkg -l
  else
    log "Package manager not detected"
  fi
}

########################
# Entry Point          #
########################

main() {
  require_root
  detect_distro
  log "IR snapshot started"
  metadata
  network_checks
  auth_checks
  user_checks
  persistence_checks
  filesystem_checks
  runtime_checks
  logging_checks
  software_inventory
  log "IR snapshot completed"
  log "Log file: $LOGFILE"
}

main "$@"

#!/bin/bash
# Author: Anthony Kwok
# Version: 1.0
# Audit SSH configuration for insecure settings

SSHD_CONFIG="/etc/ssh/sshd_config"

if [[ ! -f "$SSHD_CONFIG" ]]; then
  echo "[-] sshd_config not found"
  exit 1
fi

echo "[+] SSH hardening checks"

grep -Ei "PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|ChallengeResponseAuthentication" "$SSHD_CONFIG" | grep -v "^#"

# Linux Security Operations Scripts

A collection of **defensive Linux security scripts** for detection, incident response, and hardening audits.

Designed for **RHEL-based systems** (RHEL, Rocky, Alma, CentOS Stream) with portability across modern Linux distributions.

---

## Detection Scripts

### suspicious_process_hunter.sh
Identifies potentially malicious processes by:
- Executables running from `/tmp`, `/dev/shm`, or `/var/tmp`
- Abuse of common LOLBins (curl, wget, nc, bash -i)
- Processes without a controlling TTY

**Use case:** Initial compromise detection  
**MITRE ATT&CK:** T1059, T1105

---

### persistence_audit.sh
Audits common Linux persistence mechanisms:
- User and system cron jobs
- Enabled systemd services
- Recently modified service files

**Use case:** Post-compromise persistence discovery  
**MITRE ATT&CK:** T1053, T1543

---

### brute_force_audit.sh
Parses authentication logs to detect SSH brute force activity.

- RHEL: `/var/log/secure`
- Debian-based fallback: `/var/log/auth.log`

**Use case:** Credential access detection  
**MITRE ATT&CK:** T1110

---

## Incident Response Scripts

### network_snapshot.sh
Captures the current network state:
- Listening services
- Established connections
- Top remote IPs by connection count

**Use case:** Live incident triage and containment  
**MITRE ATT&CK:** T1046, T1071

---

### system_state_capture.sh
Provides a quick system snapshot including:
- Logged-in users
- Top CPU-consuming processes
- Disk usage
- Loaded kernel modules

**Use case:** First-response forensic context

---

## Hardening & Audit Scripts

### ssh_config_audit.sh
Audits SSH configuration for insecure settings such as:
- Root login enabled
- Password authentication
- Empty passwords

**Use case:** Security baseline validation  
**MITRE ATT&CK:** T1021

---

### user_privilege_audit.sh
Identifies excessive privilege assignments:
- UID 0 users
- Sudoers file entries
- Included sudoers.d configurations

**Use case:** Privilege escalation risk assessment  
**MITRE ATT&CK:** T1068

---

## Design Principles
- Read-only, non-destructive
- No external dependencies
- Safe for production environments
- Optimized for RHEL, portable elsewhere

---

## Disclaimer
These scripts are intended for **defensive security, detection engineering, and research purposes only**.

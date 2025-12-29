````md
# SSH Authentication Failure Detection (IR-Level)

## Overview

This repository contains an **Incident Response–grade SSH authentication failure detection script** designed for real-world SOC, IR, and detection-engineering use.

The script analyzes Linux SSH authentication logs to identify **brute force and credential abuse activity** within a configurable **time window**, producing **structured JSON output** suitable for direct SIEM ingestion (e.g., Splunk).

This project intentionally avoids assumptions common in basic scripts and reflects **production detection design principles**.

---

## Key Features

- Password **and** public-key authentication failure detection
- Time-windowed analysis (default: 15 minutes)
- Distinguishes **source IP, target user, and authentication method**
- IPv4 and IPv6 support
- Regex-based parsing (no fixed field assumptions)
- Line-delimited JSON output (Splunk-ready)
- MITRE ATT&CK tactic and technique tagging

---

## Why This Script Exists

Many SSH brute force scripts:

- Assume a fixed log format
- Only count IP addresses
- Ignore public-key authentication abuse
- Break on IPv6
- Output unstructured text

In real incident response scenarios, these limitations lead to missed detections and poor investigative context.

This script is designed to be:
- Portable across Linux distributions
- Resilient to log format variation
- Immediately actionable in IR and SOC workflows

---

## Detection Logic

An event is included if it meets **all** of the following criteria:

1. Originates from `sshd`
2. Authentication failure type:
   - `Failed password`
   - `Failed publickey`
3. Timestamp falls within the configured time window
4. Source IP and target username can be reliably extracted

Events are aggregated by:
- Source IP
- Target user
- Authentication method

---

## Supported Platforms & Logs

The script automatically selects the appropriate log file:

| Distribution | Log File |
|-------------|----------|
| RHEL / CentOS / Rocky / Alma | `/var/log/secure` |
| Debian / Ubuntu | `/var/log/auth.log` |

If no supported log file is found, the script exits safely.

---

## MITRE ATT&CK Mapping

This detection aligns with the following MITRE ATT&CK techniques:

- **Tactic:** Credential Access  
- **Technique:** Brute Force  
- **Technique ID:** T1110  
- **Sub-technique:** T1110.001 (Password Guessing)

Public-key failures may also indicate key spraying or misuse, which falls under adjacent sub-techniques of **T1110**.

---

## Example Output (JSON)

Each line represents a unique aggregation of `(IP + user + auth method)`:

```json
{
  "event_type": "ssh_auth_failure",
  "src_ip": "203.0.113.77",
  "user": "root",
  "auth_method": "password",
  "attempt_count": 187,
  "first_seen": 1705330201,
  "last_seen": 1705331045,
  "time_window_minutes": 15,
  "mitre_tactic": "Credential Access",
  "mitre_technique": "Brute Force",
  "mitre_technique_id": "T1110",
  "mitre_subtechnique": "T1110.001"
}
````

This output is **SIEM-native** and requires no post-processing.

---

## Usage

Make the script executable:

```bash
chmod +x ssh_auth_ir_detector.sh
```

Run the script:

```bash
./ssh_auth_ir_detector.sh
```

Adjust the time window (example: 30 minutes):

```bash
TIME_WINDOW_MINUTES=30 ./ssh_auth_ir_detector.sh
```

---

## SIEM Ingestion Notes (Splunk)

* Event format: Line-delimited JSON
* Recommended sourcetype: `ssh:auth:json`
* Timestamps: Epoch seconds

Useful fields for correlation:

* `src_ip`
* `user`
* `auth_method`
* `attempt_count`
* `mitre_technique_id`

---

## Incident Response Use Cases

* SSH brute force detection
* Credential stuffing identification
* Targeted account attack analysis
* Compromised SSH key investigations
* Host-based triage during incidents
* Detection engineering and purple-team validation

---

## Limitations & Assumptions

* Relies on standard syslog timestamps
* Focused on authentication failures only
* Detection-only (no automated blocking)

These constraints are intentional to preserve auditability and SIEM compatibility.

---

## Future Enhancements

Potential extensions include:

* Severity scoring
* Threshold-based alerting
* Firewall or SOAR integration
* Splunk CIM field alignment
* Separate detections for key spraying
* Lateral movement correlation

---

## License

MIT License — intended for learning, portfolio use, and defensive security research.

```
```

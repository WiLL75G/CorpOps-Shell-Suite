# Project 01 Nmap Port Scan Detection (MITRE T1046)

## Incident Summary

A TCP SYN port scan originating from `192.168.64.15` (Kali Linux attacker host) was directed at `192.168.64.12` (Ubuntu Server `wazuh-manager`). The scan probed 1,000 distinct destination ports in 37.7 milliseconds, identifying four open services. The activity was captured, analyzed, detected by a custom Bash detector, and contained via host-firewall response. The complete loop baseline → detection → response → verification → log corroboration was executed and evidenced.

## Executive Summary

Reconnaissance is the first phase of nearly every cyberattack. This investigation demonstrates how a SOC Tier 1 analyst captures, identifies, and contains a port scan using open-source tooling: `tcpdump` for packet capture, `Bash` for detection logic, and `UFW` for host-level response. Every detection finding was independently corroborated by a second evidence source, and the firewall response was validated by re-running the original attack and confirming all probed ports moved from `open` to `filtered`.

## Affected System

| Attribute | Value |
|---|---|
| Hostname | `wazuh-manager` |
| IP Address | `192.168.64.12` |
| Interface | `enp0s1` |
| Operating System | Ubuntu 24.04.4 LTS (Noble Numbat) |
| Kernel | `Linux 6.8.0-117-generic` |
| Architecture | `aarch64` |
| Role | Target host CorpOps SOC home lab |

## Investigation Methodology

### 1. Lab Readiness
Verified network path between attacker (Kali) and target (Ubuntu) ping returned 4/4 successful replies, 0% loss, `TTL=64` (Linux target confirmation).
- Screenshot: `screenshots/phase01/04_ping_test.png`

### 2. Baseline Capture
Documented Ubuntu's known-good state before the attack:
- Listening ports captured with `ss -tuln`
- Running services captured with `systemctl list-units`
- Firewall state captured UFW reported `Status: inactive` (baseline weakness)
- Host identity captured (hostname, kernel, OS release)
- Screenshots: `screenshots/phase02/01–04_*_baseline.png`

**SOC Observations:**
- UFW inactive host firewall not enforcing any rules at time of attack
- Samba services (`139/tcp`, `445/tcp`) listening on all interfaces broad attack surface
- SSH (`22/tcp`) and HTTP (`80/tcp`) listening on all interfaces expected services

### 3. Packet Capture Initiated
Started `tcpdump` on Ubuntu prior to the attack, filtered to attacker IP only:
```bash
sudo tcpdump -i enp0s1 -w logs/nmap_scan_capture.pcap host 192.168.64.15
```

### 4. Attack Simulation
Ran TCP SYN scan from Kali against Ubuntu:
```bash
sudo nmap -sS -v -oN nmap_scan_results.txt 192.168.64.12
```
Scan completed in 0.79 seconds, sent 1,001 raw packets, identified 4 open ports: `22`, `80`, `139`, `445`.

### 5. Capture Stopped
Stopped tcpdump (`Ctrl+C`). 2,198 packets captured (bidirectional both attacker probes and target responses).

### 6. Pcap Analysis
Reading the pcap revealed two overlapping traffic patterns:
- **Background noise:** Wazuh agent on Kali periodically attempting to reach `wazuh-manager` on ports `1514` and `1515` (every ~10 seconds)
- **The actual scan:** A burst of 1,000 SYN packets starting at `14:18:22.474077`, ending `14:18:22.511814`

**SOC Observations:**
- Single source port (`39183`) Nmap signature
- Single sequence number reused across all SYN probes (`1543761786`) Nmap signature
- Identical TCP window size (`1024`) on every probe Nmap signature
- Sub-millisecond inter-packet spacing humanly impossible
- Open ports replied with `[S.]` (SYN-ACK); attacker immediately replied with `[R]` (RST) half-open scan signature

### 7. Detection Script Developed
Built `scripts/nmap_scan_detector.sh` a Bash detector that:
- Reads any `.pcap` file
- Filters out known-good baseline traffic (Wazuh ports `1514`/`1515`)
- Counts distinct destination ports targeted by SYN packets from a single source
- Raises ALERT when distinct-port count ≥ threshold (default: 100)
- Writes structured alerts to `logs/scan_alerts.log` (SIEM-ingestible format)
- Returns non-zero exit code on alert (for SIEM/orchestration integration)

### 8. Detection Executed
Running the detector against the capture produced:
```
[FINDING] Source IP:          192.168.64.15
[FINDING] Total SYN probes:   1000
[FINDING] Distinct dst ports: 1000
[FINDING] First probe:        14:18:22.474077
[FINDING] Last probe:         14:18:22.511814

[ALERT] PORT SCAN DETECTED -- MITRE T1046
```

Alert appended to `logs/scan_alerts.log`:
```
2026-06-02T18:04:37+00:00 | ALERT | T1046 | src=192.168.64.15 | probes=1000 | ports=1000 | window=14:18:22.474077-14:18:22.511814
```

### 9. Response Applied
Hardened the host firewall:
1. Allowed SSH explicitly (lockout prevention)
2. Created `deny from 192.168.64.15` rule
3. Enabled UFW logging at `medium` level
4. Activated UFW
5. Re-ordered rules so the DENY rule sits at position 1 (above broad ALLOW rules)

### 10. Response Verified
Re-ran the same Nmap probe from Kali:
```
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
139/tcp  filtered netbios-ssn
445/tcp  filtered microsoft-ds
```
All four previously-open ports now report `filtered` UFW silently dropping every probe.

### 11. Block Corroborated in Logs
`/var/log/ufw.log` shows entries with `[UFW BLOCK]` and `[UFW AUDIT]` tags, `SRC=192.168.64.15`, `WINDOW=1024` the Nmap fingerprint preserved in defender-side logs.

## Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Source IP | `192.168.64.15` |
| Source MAC | `1E:7D:F7:54:89:A1` |
| Source port | `39183` |
| TCP sequence (initial) | `1543761786` (reused Nmap fingerprint) |
| TCP window size | `1024` (Nmap probe template) |
| Probe count | 1,000 SYN packets |
| Distinct destination ports | 1,000 |
| Scan time window | `14:18:22.474077 → 14:18:22.511814` |
| Scan duration | 37.7 ms |
| Scan rate | ~26,500 probes/sec |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Discovery | Network Service Discovery | T1046 | Adversary probed 1,000 TCP ports on target host to enumerate listening services. |

## SOC Analyst Findings

- TCP SYN port scan confirmed from `192.168.64.15` → `192.168.64.12`
- 1,000 distinct destination ports probed in 37.7 milliseconds categorically non-human
- Four services exposed pre-block: SSH (22), HTTP (80), NetBIOS (139), SMB (445)
- Pre-attack host firewall posture was `inactive` documented baseline weakness
- Detection threshold (100 distinct ports) exceeded by 10x
- Nmap signature confirmed via single source port, reused sequence number, fixed TCP window
- No post-scan exploitation observed in this capture window scan-stage activity only

## SOC Analyst Response

1. Allowed SSH at firewall (admin lockout prevention)
2. Created explicit DENY rule for attacker source IP
3. Enabled `medium`-level UFW logging
4. Activated UFW (closed baseline gap from Phase 2)
5. Re-ordered rules DENY at position 1, above broad ALLOW rules
6. Validated block via repeat-scan from attacker (all probed ports now `filtered`)
7. Corroborated block via `/var/log/ufw.log` entries

## Analyst Insight

The most striking finding wasn't the open ports it was the 37.7-millisecond scan duration. Speed alone is forensic-grade evidence; no human or legitimate application opens 1,000 connections in under a second. This shapes detection design: behavioral indicators (rate, parallelism, sequence reuse) generalize across attackers and tools, while signature matching can be evaded. The pcap also revealed environmental noise legitimate Wazuh agent traffic on ports 1514/1515 that the detector had to filter, mirroring real SOC work where separating signal from noise is half the job.

## Learning Outcome

- Built a production-shaped Bash detector that consumes packet captures and emits structured SIEM-ready alerts
- Understood why firewall rule order matters specific DENY must precede broad ALLOW
- Practiced filtering legitimate baseline traffic out of attack analysis
- Generated multiple independent evidence trails: pcap, alert log, firewall log
- Executed the full SOC loop: baseline → attack → detect → respond → verify → corroborate
- Mapped technical findings to MITRE ATT&CK T1046

## Repository Structure

```
Project-01-Nmap-Detection/
├── README.md
├── baseline/
│   ├── firewall_baseline.txt
│   ├── host_identity_baseline.txt
│   ├── listening_ports_baseline.txt
│   └── running_services_baseline.txt
├── scripts/
│   └── nmap_scan_detector.sh
├── logs/
│   ├── nmap_scan_capture.pcap
│   └── scan_alerts.log
└── screenshots/
    ├── phase01/
    └── phase02/
```

## Conclusion

Project 01 executed the complete SOC Tier 1 incident response workflow for a network reconnaissance event. Baseline confirmed pre-attack state, packet capture preserved forensic evidence, a custom Bash detector identified the scan and produced a SIEM-ready alert, and the response (UFW deny rule with corrected ordering) was independently verified by both an attacker-side re-scan and defender side firewall logs. The detection logic distinct-port count from a single source within a short window generalizes beyond Nmap to most scan tools, and the alert format is structured for direct ingestion into Splunk or any other SIEM. This loop is the operational core of SOC analyst work.

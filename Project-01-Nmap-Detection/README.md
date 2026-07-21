# Nmap Port Scan Detection (MITRE T1046)

1,000 ports probed in 37.7 milliseconds, a scan rate no human or legitimate application can produce. This lab captures that scan, detects it with a custom Bash tool, blocks the source at the firewall, and then proves the block worked by re-running the attack and watching every port flip from open to filtered.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Detection scripting and host response |
| Attack | TCP SYN port scan, 1,000 ports |
| Attacker | Kali, 192.168.64.15 |
| Target | wazuh-manager, 192.168.64.12, Ubuntu 24.04.4 |
| Scan Duration | 37.7 ms, ~26,500 probes/sec |
| Detection | Custom Bash detector on pcap, threshold 100 ports |
| Response | UFW deny rule, verified by re-scan and logs |
| MITRE | T1046 |

## What This Is

A complete SOC Tier 1 workflow for a network reconnaissance event, from baseline through detection, response, and verification. A TCP SYN port scan from a Kali attacker is captured with tcpdump, detected by a hand-written Bash tool, contained with a host firewall rule, and the containment is independently proven.

Reconnaissance is the first phase of nearly every cyberattack. This project shows how a Tier 1 analyst captures, identifies, and contains it using open-source tooling: tcpdump for packet capture, Bash for detection logic, and UFW for host-level response. Every finding is corroborated by a second evidence source.

## Incident Summary

A TCP SYN port scan originating from `192.168.64.15` (Kali Linux attacker host) was directed at `192.168.64.12` (Ubuntu Server `wazuh-manager`). The scan probed 1,000 distinct destination ports in 37.7 milliseconds, identifying four open services.

The activity was captured, analyzed, detected by a custom Bash detector, and contained via host-firewall response. The complete loop, baseline to detection to response to verification to log corroboration, was executed and evidenced. That closed loop is the point: detecting the scan is half a job, proving the fix held is the other half.

## Affected System

| Attribute | Value |
| --- | --- |
| Hostname | `wazuh-manager` |
| IP Address | `192.168.64.12` |
| Interface | `enp0s1` |
| Operating System | Ubuntu 24.04.4 LTS (Noble Numbat) |
| Kernel | `Linux 6.8.0-117-generic` |
| Architecture | `aarch64` |
| Role | Target host, CorpOps SOC home lab |

## Investigation Methodology

### 1. Lab Readiness

Verified network path between attacker (Kali) and target (Ubuntu): ping returned 4/4 successful replies, 0% loss, `TTL=64` (Linux target confirmation).

- Screenshot: `screenshots/phase01/04_ping_test.png`

### 2. Baseline Capture

Documented Ubuntu's known-good state before the attack: listening ports with `ss -tuln`, running services with `systemctl list-units`, firewall state (UFW reported `Status: inactive`, a baseline weakness), and host identity.

- Screenshots: `screenshots/phase02/01–04_*_baseline.png`

**SOC Observations**

UFW was inactive, so the host firewall was enforcing nothing at the time of attack. Samba services (`139/tcp`, `445/tcp`) were listening on all interfaces, a broad attack surface, alongside expected SSH (`22/tcp`) and HTTP (`80/tcp`). Capturing this weakness before the attack is what lets the response step show a measurable improvement rather than an asserted one.

### 3. Packet Capture Initiated

Started `tcpdump` on Ubuntu prior to the attack, filtered to the attacker IP only:

```bash
sudo tcpdump -i enp0s1 -w logs/nmap_scan_capture.pcap host 192.168.64.15
```

### 4. Attack Simulation

Ran a TCP SYN scan from Kali against Ubuntu:

```bash
sudo nmap -sS -v -oN nmap_scan_results.txt 192.168.64.12
```

Scan completed in 0.79 seconds, sent 1,001 raw packets, identified 4 open ports: `22`, `80`, `139`, `445`.

### 5. Capture Stopped

Stopped tcpdump (`Ctrl+C`). 2,198 packets captured, bidirectional, covering both attacker probes and target responses.

### 6. Pcap Analysis

Reading the pcap revealed two overlapping traffic patterns: background noise from the Wazuh agent on Kali periodically reaching `wazuh-manager` on ports `1514` and `1515` every ~10 seconds, and the actual scan, a burst of 1,000 SYN packets from `14:18:22.474077` to `14:18:22.511814`.

**SOC Observations**

The scan carried a stack of Nmap signatures: a single source port (`39183`), a single sequence number reused across all SYN probes (`1543761786`), an identical TCP window size (`1024`) on every probe, and sub-millisecond inter-packet spacing that is humanly impossible. Open ports replied with `[S.]` (SYN-ACK), and the attacker immediately replied with `[R]` (RST), the half-open scan signature. Any one of these is suggestive; together they are a fingerprint.

### 7. Detection Script Developed

Built `scripts/nmap_scan_detector.sh`, a Bash detector that reads any `.pcap`, filters out known-good baseline traffic (Wazuh ports `1514`/`1515`), counts distinct destination ports targeted by SYN packets from a single source, raises an ALERT when the distinct-port count meets or exceeds a threshold (default 100), writes structured alerts to `logs/scan_alerts.log` in SIEM-ingestible format, and returns a non-zero exit code on alert for orchestration integration.

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

Hardened the host firewall: allowed SSH explicitly (lockout prevention), created a `deny from 192.168.64.15` rule, enabled UFW logging at `medium` level, activated UFW, and re-ordered rules so the DENY rule sits at position 1, above the broad ALLOW rules.

### 10. Response Verified

Re-ran the same Nmap probe from Kali:

```
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
139/tcp  filtered netbios-ssn
445/tcp  filtered microsoft-ds
```

All four previously-open ports now report `filtered`, UFW silently dropping every probe. This is the step that turns "I applied a rule" into "I proved the rule works."

### 11. Block Corroborated in Logs

`/var/log/ufw.log` shows entries tagged `[UFW BLOCK]` and `[UFW AUDIT]`, `SRC=192.168.64.15`, `WINDOW=1024`, the Nmap fingerprint preserved in defender-side logs. The same signature that identified the attack now confirms the block, a clean evidence chain from both sides.

## Indicators of Compromise (IOCs)

| IOC Type | Value |
| --- | --- |
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
| --- | --- | --- | --- |
| Discovery | Network Service Discovery | T1046 | Adversary probed 1,000 TCP ports on target host to enumerate listening services. |

## Findings

- TCP SYN port scan confirmed from `192.168.64.15` to `192.168.64.12`.
- 1,000 distinct destination ports probed in 37.7 milliseconds, categorically non-human.
- Four services exposed pre-block: SSH (22), HTTP (80), NetBIOS (139), SMB (445).
- Pre-attack host firewall posture was `inactive`, a documented baseline weakness.
- Detection threshold (100 distinct ports) exceeded by 10x.
- Nmap signature confirmed via single source port, reused sequence number, and fixed TCP window.
- No post-scan exploitation observed in this capture window, scan-stage activity only.

## Response

1. Allowed SSH at the firewall (admin lockout prevention).
2. Created an explicit DENY rule for the attacker source IP.
3. Enabled `medium`-level UFW logging.
4. Activated UFW, closing the baseline gap from Phase 2.
5. Re-ordered rules, DENY at position 1, above broad ALLOW rules.
6. Validated the block via repeat-scan from the attacker, all probed ports now `filtered`.
7. Corroborated the block via `/var/log/ufw.log` entries.

## The SOC Angle

The most striking finding was not the open ports, it was the 37.7-millisecond scan duration.

Speed alone is forensic-grade evidence. No human and no legitimate application opens 1,000 connections in under a second, which means the timing is a detection signal that holds no matter what tool the attacker uses. That shapes the detection design: behavioral indicators, rate, parallelism, sequence reuse, generalize across attackers, while signature matching can be evaded by changing one variable.

The pcap also carried environmental noise, legitimate Wazuh agent traffic on ports 1514/1515, that the detector had to filter out. That is not an inconvenience, it is the job. Separating signal from noise is half of Tier 1 work, and a detector that cannot do it fires on its own monitoring stack.

## What This Demonstrates

Building a production-shaped Bash detector that consumes packet captures and emits structured SIEM-ready alerts.

Understanding why firewall rule order matters, a specific DENY must precede a broad ALLOW.

Filtering legitimate baseline traffic out of attack analysis.

Generating multiple independent evidence trails: pcap, alert log, firewall log.

Executing the full SOC loop, baseline to attack to detect to respond to verify to corroborate.

Reading Nmap's fingerprint from raw packets rather than trusting a tool's label.

Mapping technical findings to MITRE ATT&CK T1046.

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

Project 01 executed the complete SOC Tier 1 incident response workflow for a network reconnaissance event. Baseline confirmed the pre-attack state, packet capture preserved forensic evidence, a custom Bash detector identified the scan and produced a SIEM-ready alert, and the response (a UFW deny rule with corrected ordering) was independently verified by both an attacker-side re-scan and defender-side firewall logs. The detection logic, distinct-port count from a single source within a short window, generalizes beyond Nmap to most scan tools, and the alert format is structured for direct ingestion into Splunk or any other SIEM. This loop is the operational core of SOC analyst work.

---

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=flat&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

[![Blue Team Notes](https://img.shields.io/badge/Blue_Team_Notes-WilliamInCyber-1F6FEB?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![Projects](https://img.shields.io/badge/Suite-8_Projects-1F6FEB?style=flat)](https://github.com/WiLL75G)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C5221F?style=flat)](https://attack.mitre.org)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk-65A637?style=flat&logo=splunk&logoColor=white)](https://www.splunk.com)
[![Shell](https://img.shields.io/badge/Shell-Bash_+_Python-E57000?style=flat&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

# CorpOps Shell Suite

The most common gap in early-career SOC hiring is not technical knowledge, it is proof of analyst thinking.

Candidates who can run tools are everywhere. Candidates who can look at 1,000 TCP connections in 37 milliseconds and recognise the behavioural fingerprint, write a script that catches it, produce a SIEM-ready alert, apply a correctly-ordered firewall response, and independently verify it held, those are the analysts SOC managers actually want to hire.

CorpOps Shell Suite was built to be that proof.

Eight projects. Each one simulates a real attacker technique against a live home lab environment, then works through the complete defender's workflow from the ground up. Every project produces a structured SOC Tier 1 incident report, a detection or analysis script, full evidence artifacts (packet captures, alert logs, screenshots), and MITRE ATT&CK mapping.

Not tutorial output. Investigation documentation, the kind a Tier 1 analyst produces for escalation review.

The lab runs inside a fictional enterprise environment, Nexus Corp, giving each investigation a realistic operational context, an attacker host, a target host, an endpoint, and a SIEM.

---

## Lab Environment

| Component | Role |
|---|---|
| Kali Linux (UTM VM) | Attacker simulation |
| Ubuntu Server (UTM VM) | Target host |
| Windows 11 (UTM VM) | Endpoint simulation |
| Splunk Enterprise (macOS host) | SIEM / log analysis |

---

## Projects

| # | Project | MITRE ATT&CK Technique | Status |
|---|---|---|---|
| 01 | [Nmap Port Scan Detection](./Project-01-Nmap-Detection/) | T1046 Network Service Discovery | Complete |
| 02 | [WebSift Web Asset Audit](./Project-02-WebSift-Audit/) | T1593 Search Open Websites/Domains | Complete |
| 03 | [Tookie-OSINT Digital Footprint](./Project-03-Tookie-OSINT-Footprint/) | T1589 Gather Victim Identity Information | Complete |
| 04 | [User-Scanner Email/Username OSINT](./Project-04-UserScanner/) | T1589 Gather Victim Identity Information | Complete |
| 05 | [IP Commands Threat Intel Enrichment](./Project-05-IPCommander/) | T1071 Application Layer Protocol | Complete |
| 06 | Whois Domain Spoofing Detection | T1566 Phishing | Coming Soon |
| 07 | EternalView Recon & Defense Mapping | T1595 Active Scanning | Coming Soon |
| 08 | Python SMTP Phishing Header Analysis | T1566 Phishing | Coming Soon |

---

## Project Structure

Every project follows the same folder convention and README format.

Project-XX-Name/
├── README.md
├── baseline/
├── scripts/
├── logs/
└── screenshots/
    ├── phase01/
    └── phase02/

Each README follows this locked structure,

Title, Incident Summary, Executive Summary, Affected System, Investigation Methodology, IOCs, MITRE ATT&CK Mapping, SOC Analyst Findings, SOC Analyst Response, Analyst Insight, Learning Outcome, Repository Structure, Conclusion

---

## Detection Philosophy

Every project in this suite approaches detection from the defender's perspective first.

Attack simulation is not the goal, it is the trigger. The goal is to answer,

What does this technique look like on the wire? What does it leave in logs? How do you write a rule or script that catches it reliably? How do you respond, verify the fix, and document the chain of evidence?

Behavioral detection (rate, timing, pattern) is favoured over signature detection, because signatures can be evaded and behaviour cannot.

---

## Stack

| Tool | Purpose |
|---|---|
| Bash | Detection scripts and log parsing |
| Python | Enrichment and analysis tooling |
| tcpdump | Packet capture and pcap analysis |
| Nmap | Attack simulation (reconnaissance) |
| Splunk Enterprise | SIEM correlation and dashboarding |
| UFW / iptables | Host firewall response |
| MITRE ATT&CK | Technique mapping and documentation |

---

## Repository Structure

CorpOps-Shell-Suite/
├── README.md
├── Project-01-Nmap-Detection/
├── Project-02-WebSift-Audit/
├── Project-03-Tookie-OSINT-Footprint/
├── Project-04-UserScanner/
├── Project-05-IPCommander/
├── Project-06-Whois-Spoofing/
├── Project-07-EternalView-Recon/
└── Project-08-SMTP-Phishing/

---

## Author

SOC Analyst, Blue Team, ISC2 Certified in Cybersecurity (CC)

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

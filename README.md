[![Blue Team Notes](https://img.shields.io/badge/Blue_Team_Notes-WilliamInCyber-1F6FEB?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![Projects](https://img.shields.io/badge/Suite-8_Projects-1F6FEB?style=flat)](https://github.com/WiLL75G)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C5221F?style=flat)](https://attack.mitre.org)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk-65A637?style=flat&logo=splunk&logoColor=white)](https://www.splunk.com)
[![Shell](https://img.shields.io/badge/Shell-Bash_+_Python-E57000?style=flat&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

# CorpOps Shell Suite

Most cybersecurity portfolios say the same thing: "I set up a home lab and ran some tools."

This one is different.

CorpOps Shell Suite is eight structured investigations, each one built around a real attacker technique, run inside a controlled lab environment, and documented the way a SOC analyst actually works not a tutorial, not a walkthrough, but a complete defender's workflow from first packet to final report.

Every project answers four questions:

- What does this attack look like on the wire or in the logs?
- How do you build a tool or script that catches it?
- What do you do when you find it?
- How do you prove what happened?

The lab runs inside a fictional enterprise **Nexus Corp** with an attacker host, a target server, an endpoint, and a SIEM. Every project is self-contained and every README is written in SOC Tier 1 incident report format the same format a real analyst would hand to Tier 2 for escalation.

---

## Lab Environment

| Component | Role |
|---|---|
| Kali Linux (UTM VM) | Attacker simulates the threat |
| Ubuntu Server (UTM VM) | Target the system being defended |
| Windows 11 (UTM VM) | Endpoint simulation |
| Splunk Enterprise (macOS host) | SIEM log analysis and alerting |

---

## The 8 Projects

Each project covers a different attacker technique and produces a detection script or analysis tool, evidence artifacts, and a full MITRE-mapped report.

| # | Project | What It Detects | MITRE | Status |
|---|---|---|---|---|
| 01 | [Nmap Port Scan Detection](./Project-01-Nmap-Detection/) | TCP SYN port scans across 1,000 ports in 37ms | T1046 | ✅ Complete |
| 02 | [WebSift Web Asset Audit](./Project-02-WebSift-Audit/) | Public web footprint server versions, missing security headers | T1593 | ✅ Complete |
| 03 | [Tookie-OSINT Digital Footprint](./Project-03-Tookie-OSINT-Footprint/) | Username presence across 8 platforms | T1589 | ✅ Complete |
| 04 | [User-Scanner Email/Username OSINT](./Project-04-UserScanner/) | Email domain analysis, MX records, platform enumeration | T1589 | ✅ Complete |
| 05 | [IP Commands Threat Intel Enrichment](./Project-05-IPCommander/) | IP geolocation, abuse reputation, reverse DNS | T1071 | ✅ Complete |
| 06 | [Whois Domain Spoofing Detection](./Project-06-Whois-Spoofing-Detection/) | Typosquat domain registration phishing infrastructure | T1566 | ✅ Complete |
| 07 | [EternalView Recon & Defense Mapping](./Project-07-EternalView-Recon/) | Active recon mapped to MITRE techniques and hardening actions | T1595 | ✅ Complete |
| 08 | [Python SMTP Phishing Header Analysis](./Project-08-SMTP-Phishing-Analysis/) | Email header forensics SPF/DKIM/DMARC, phishing scoring | T1566 | ✅ Complete |

---

## What Each Project Produces

Every project delivers the same four things:

```
Project-XX-Name/
├── README.md          — SOC Tier 1 incident report
├── scripts/           — detection or analysis tool
├── output/            — structured report from the tool
└── screenshots/       — visual evidence from every step
```

Every README follows this structure:

> Title → Incident Summary → Executive Summary → Affected System → Investigation Methodology → IOCs → MITRE ATT&CK Mapping → SOC Analyst Findings → SOC Analyst Response → Analyst Insight → Learning Outcome → Repository Structure → Conclusion

---

## Why This Suite Exists

Most early-career SOC candidates can run a tool. Very few can explain what the output means, tie it to a MITRE technique, write a detection that catches it, and document the chain of evidence.

That gap is what this suite closes.

Each project starts with attacker thinking what would someone actually do here? and ends with defender documentation what happened, how was it caught, what was done about it, and how was the fix verified?

That loop is the job. This suite is proof of doing it.

---

## Detection Approach

Behavioral detection over signature detection always.

Signatures describe known bad. Behavior describes how bad things move. An attacker can change a file hash, a domain name, or an IP address in seconds. They cannot change the fact that 1,000 port probes in 37 milliseconds is not human behavior.

Every project in this suite looks for behavioral signals rate, timing, pattern, mismatch rather than static rules that break the moment the attacker changes one variable.

---

## Stack

| Tool | Purpose |
|---|---|
| Python | OSINT tools, enrichment pipelines, email analysis |
| Bash | Detection scripts, log parsing, alert generation |
| Nmap | Attack simulation port scanning |
| tcpdump | Packet capture forensic evidence |
| Splunk Enterprise | SIEM log correlation and dashboarding |
| UFW / iptables | Host firewall response and verification |
| MITRE ATT&CK | Technique mapping across all 8 projects |

---

## Repository Structure

```
CorpOps-Shell-Suite/
├── README.md
├── Project-01-Nmap-Detection/
├── Project-02-WebSift-Audit/
├── Project-03-Tookie-OSINT-Footprint/
├── Project-04-UserScanner/
├── Project-05-IPCommander/
├── Project-06-Whois-Spoofing-Detection/
├── Project-07-EternalView-Recon/
└── Project-08-SMTP-Phishing-Analysis/
```

---

## Author

SOC Analyst | Blue Team | ISC2 Certified in Cybersecurity (CC)

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

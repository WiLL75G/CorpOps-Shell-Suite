# EternalView: Recon & Defense Mapping (MITRE T1595)

> Built a custom Python tool that performs structured active reconnaissance against an authorized target and maps every finding, open ports, service banners, OS fingerprint, directly to a MITRE ATT&CK technique and a specific defensive hardening action.

3 open ports, an OS fingerprinted at 97% confidence, and one SSH banner that hands an attacker four intelligence points in a single string. EternalView does not stop at listing what is open, it answers the question most scanner output leaves hanging: what does each finding mean, and what do I do about it.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Active recon and defense mapping, Python |
| Tool | EternalView, five modules, built from scratch |
| Target | 192.168.64.12, wazuh-manager, Ubuntu Server |
| Open Ports | 3, SSH 22, NetBIOS 139, SMB 445 |
| OS Fingerprint | Linux 4.15 / 5.19, 97% accuracy |
| Standout Finding | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 banner |
| Cross-Reference | Port 80 open in Project 01, absent here |
| MITRE | T1595, T1021.004, T1021.002 |

## What This Is

An attacker scanning your infrastructure does not stop at knowing which ports are open. They read service banners to identify exact software versions, fingerprint the OS to narrow exploit selection, and correlate every finding with known CVEs. The scan takes seconds; the intelligence it produces shapes every subsequent attack decision.

EternalView runs that same structured reconnaissance from the defender's side first, against an authorized target in a controlled lab, and pairs every finding with the MITRE technique it enables and a specific hardening action. Not a generic "patch your systems," but a targeted control tied to the exact service and technique the finding represents.

Tested against Ubuntu Server (`192.168.64.12`, `wazuh-manager`), EternalView found 3 open ports, fingerprinted the OS at 97% confidence, extracted exact service version banners, and produced a MITRE-mapped defense report in a single run.

## Executive Summary

MITRE ATT&CK T1595 (Active Scanning) describes adversaries actively probing infrastructure to enumerate attack surface before exploitation. Unlike passive OSINT, active scanning sends packets to the target and interprets the responses, open ports, service banners, TCP/IP stack behavior. The intelligence gathered directly shapes which exploits an attacker selects and which services they target.

EternalView runs five sequential modules: a TCP SYN port scan (via python-nmap), service banner grabbing (a banner like `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` is a direct CVE lookup waiting to happen), OS fingerprinting (TCP/IP stack analysis with a confidence percentage), MITRE mapping (every open port to the technique it enables and a specific defense, from a table covering 16 common services), and a recon-to-defense report that pairs every attacker capability with a defender action.

Against `192.168.64.12`, the tool confirmed 3 open ports (SSH, NetBIOS, SMB), identified the OS as Linux with 97% accuracy, and mapped all findings to two MITRE techniques across three distinct hardening recommendations.

## Audit Target

| Attribute | Value |
| --- | --- |
| Target IP | `192.168.64.12` |
| Hostname | `wazuh-manager` (Ubuntu Server) |
| OS Fingerprint | Linux 4.15, 5.19 (97% accuracy) |
| Open ports found | 3 |
| Scan type | TCP SYN scan with service version detection and OS fingerprinting |
| Tool | `eternalview.py`, custom Python, built from scratch |
| Environment | Kali Linux (attacker host), python-nmap, Nmap binary |

## Scope and Authorization

This scan was conducted against an authorized home lab target (`192.168.64.12`) on an isolated UTM virtual network. Active scanning sends packets directly to the target and constitutes network intrusion if performed against systems without explicit authorization. EternalView is designed for use against systems you own or are explicitly authorized to test. This is the one project in the suite that touches the target directly, and the authorization line is correspondingly firmer.

## Investigation Methodology

### 1. Environment Setup

Installed `python-nmap` for both the standard user and root environments. The SYN scan module requires raw socket access, which requires root privileges, so the library must be available in the root Python environment as well as the standard one.

*Screenshot: `02_python_environment.png`*

**Analyst note**

The need to install the library twice (user and root) is a common lab gotcha. In production this would be handled by a virtual environment or a Docker container running the tool with appropriate privileges, the kind of packaging detail that separates a script that works on your machine from a tool that works on anyone's.

### 2. Module 1: TCP Port Scan

Ran a TCP SYN scan against 16 commonly targeted ports using Nmap's service version detection flag to pull banners simultaneously with the port state check.

*Screenshot: `03a_port_scan.png`*

**Open ports found:**

| Port | Protocol | Service | State |
| --- | --- | --- | --- |
| 22 | tcp | ssh | OPEN |
| 139 | tcp | netbios-ssn | OPEN |
| 445 | tcp | netbios-ssn | OPEN |

**Notable baseline change:** Port 80 (HTTP) was open in the Project 01 baseline scan. It does not appear here. Either the web service has stopped or a firewall rule is filtering it from Kali's source IP. This discrepancy would warrant investigation in a real environment, because the unexplained disappearance of a previously open service is as interesting as an unexpected new one, and only a defender who kept the baseline would ever notice.

### 3. Module 2: Service Banner Summary

Extracted the exact version string each service advertised in its response headers.

*Screenshot: `03b_banner_os.png`*

**Banners retrieved:**

| Port | Banner | Attacker Intelligence Value |
| --- | --- | --- |
| 22 | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` | Exact version, exact OS distribution, exact package build, direct CVE lookup |
| 139 | `Samba smbd 4` | SMB service confirmed, major version known |
| 445 | `Samba smbd 4` | Same Samba instance, both legacy and modern SMB ports exposed |

### 4. Module 3: OS Fingerprinting

Nmap analyzed TCP/IP stack behavior to identify the operating system.

**Result:** Linux 4.15, 5.19 (97% accuracy)

*Screenshot: `03b_banner_os.png`*

### 5. Module 4: MITRE ATT&CK Mapping

*Screenshot: `03c_mitre_mapping.png`*

| Port | MITRE Technique | Defense |
| --- | --- | --- |
| 22 (SSH) | T1021.004 Remote Services: SSH | Enforce key-only auth, disable root login, deploy fail2ban |
| 139 (NetBIOS) | T1021.002 SMB/NetBIOS | Block at perimeter, disable if unused, monitor for lateral movement |
| 445 (SMB) | T1021.002 Remote Services: SMB | Block at perimeter if unused, patch EternalBlue, require SMB signing |

### 6. Module 5: Report Generation

Consolidated all findings into `output/ubuntu_recon_report.txt`.

*Screenshot: `03d_report.png`*

## Threat Intelligence Findings

| Finding | Attacker Value | Defender Action |
| --- | --- | --- |
| SSH open (port 22) | Remote access vector confirmed | Enforce key-only auth, deploy fail2ban, disable root SSH |
| Banner: `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` | Exact version enables targeted CVE lookup | Suppress version in SSH banner (`VersionAddendum none` in sshd_config) |
| SMB open (port 445) | Lateral movement and file share enumeration vector | Block at perimeter if not required, require SMB signing |
| NetBIOS open (port 139) | Legacy SMB vector, name service enumeration | Disable NetBIOS over TCP/IP if SMBv2+ is sufficient |
| OS: Linux 4.15, 5.19 (97%) | Narrows exploit selection to Linux-specific techniques | Suppress where possible via firewall and banner hardening |
| Port 80 absent (was open in baseline) | May indicate service down or filtering | Investigate discrepancy, update asset inventory |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
| --- | --- | --- | --- |
| Discovery | Active Scanning | T1595 | Structured port scan, banner grab, and OS fingerprint against target infrastructure |
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH exposed on port 22 with version-disclosing banner |
| Lateral Movement | Remote Services: SMB | T1021.002 | Samba SMB exposed on ports 139 and 445 |

## Findings

- Three open ports confirmed: SSH (22), NetBIOS (139), SMB (445). The same SMB exposure identified in the Project 01 baseline remains unremediated.
- The SSH banner discloses the exact software version and Ubuntu package build, enabling direct CVE lookup without any further reconnaissance.
- OS fingerprinting returned 97% confidence for Linux 4.15, 5.19, high enough to act on for exploit selection.
- Port 80 was open in the Project 01 baseline and is absent here. The reason is unconfirmed and requires investigation.
- Both legacy (139) and modern (445) SMB ports are exposed, indicating Samba is configured to support both NetBIOS and direct SMB connections.

## Response

1. Suppress the SSH version banner by adding `VersionAddendum none` to `/etc/ssh/sshd_config`.
2. Enforce SSH key-only authentication and disable password-based SSH login.
3. Deploy fail2ban on the SSH service to automatically block IPs that exceed failed login thresholds.
4. Block SMB ports 139 and 445 at the host firewall if Samba is not required. If it is required, restrict access to authorized IP ranges only and enforce SMB signing.
5. Investigate the port 80 discrepancy between the Project 01 baseline and this scan.
6. Run EternalView quarterly against all lab hosts to catch service and banner changes between scheduled security reviews.

## The SOC Angle

The most important output from this scan was not the list of open ports, it was the SSH banner.

`OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` in a single string gives an attacker the software, the version, the distribution, and the package build. Four data points from one TCP response, before any exploit is attempted. Banner suppression is not security through obscurity, it is removing an unnecessary intelligence gift. An attacker who cannot read the exact version from a banner has to guess or test, which introduces noise and time, and more work means more log entries, which means more chances for a defender to catch them.

The port 80 discrepancy is the other finding worth carrying forward, and it is the one that ties this project to Project 01. A baseline that no longer matches current reality is a gap in situational awareness. Unexplained changes to a host's service profile are always worth investigating before being accepted as normal, and the only reason this change was visible at all is that an earlier scan was kept and compared. That is the argument for running the same scan against the same target over time.

## What This Demonstrates

Building a five-module Python active-reconnaissance and defense-mapping tool from scratch, integrating python-nmap and a built-in MITRE table covering 16 common services.

Understanding the difference between passive OSINT (Projects 02 through 06) and active scanning (T1595), which produces richer intelligence but leaves a detectable footprint in target logs.

Reading service banners as an analyst, identifying what each discloses and the specific hardening action that removes that disclosure.

Identifying a baseline discrepancy (port 80 absent vs present in Project 01) by comparing the same scan against the same target over time.

Applying recon-to-defense mapping, connecting each attacker capability directly to the control that removes or degrades it.

## Repository Structure

```
Project-07-EternalView/
├── README.md
├── scripts/
│   └── eternalview.py
├── output/
│   └── ubuntu_recon_report.txt
├── reports/
└── screenshots/
    ├── 01_folder_structure.png
    ├── 02_python_environment.png
    ├── 03a_port_scan.png
    ├── 03b_banner_os.png
    ├── 03c_mitre_mapping.png
    └── 03d_report.png
```

## Conclusion

EternalView demonstrates active reconnaissance end to end, from raw port scan through service banner extraction, OS fingerprinting, and MITRE ATT&CK mapping, producing a report that pairs every attacker capability with a defender action. The SSH banner finding illustrates why banner hardening matters: four pieces of intelligence from one TCP response is not acceptable exposure on a production host. The SMB finding echoes the Project 01 baseline, confirming that an unaddressed exposure does not go away on its own. Running structured recon against your own infrastructure, reading what it reveals, and acting on what you find is the operational loop EternalView is built to support.

---

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=flat&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

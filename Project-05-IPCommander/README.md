# IP-Commander: Threat Intelligence Enrichment (MITRE T1071)

> Built a custom Python tool that takes a single IP address and returns geolocation, abuse reputation, and reverse DNS in one structured report, the enrichment pipeline a SOC analyst runs every time an unfamiliar IP shows up in the logs.

Three independent sources, one verdict, in seconds: Google-owned infrastructure in Ashburn, a 0/100 abuse score standing on 116 historical reports, and a reverse DNS of dns.google. The score alone would be thin. The 116 reports behind it are what turn "no data" into "confirmed clean," and knowing that difference is the whole job.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Threat intel enrichment tooling, Python |
| Tool | IP-Commander, four-module pipeline, built from scratch |
| Validation Target | 8.8.8.8, Google Public DNS |
| Key Result | 0/100 abuse, 116 reports, dns.google, LOW RISK |
| Data Sources | ip-api.com, AbuseIPDB, Python socket |
| Environment | Kali, Python 3.13, requests |
| MITRE | T1071, as the technique this enrichment helps assess |
| Posture | Passive, read-only lookups |

## What This Is

A SIEM alert fires. There is an unfamiliar IP address in the logs. The analyst's first question is always the same: is this address malicious, and what do we actually know about it?

Answering that by hand means three or four browser tabs, a geolocation lookup, an abuse-database check, a reverse DNS query, stitched together manually. IP-Commander automates that pipeline into a single command: geolocation, abuse reputation, reverse DNS, and a consolidated verdict.

Tested against `8.8.8.8` (Google's public DNS), the tool resolved the address to Google LLC infrastructure in Ashburn, Virginia, confirmed a `0/100` abuse confidence score despite 116 historical reports, and resolved the reverse DNS hostname `dns.google`, producing a complete, evidence-backed LOW RISK verdict in seconds.

## Executive Summary

MITRE ATT&CK T1071 (Application Layer Protocol) describes adversaries using standard protocols, HTTP, DNS, SMTP, to blend command-and-control traffic into legitimate network activity. Because the traffic looks ordinary at the protocol level, the IP address itself becomes one of the more reliable signals a defender has, and enrichment is what turns a bare IP into an actionable decision.

A note on how this project uses that mapping: IP-Commander does not detect T1071 traffic on the wire. It is an enrichment tool that scores an IP already surfaced by some other detection. Enrichment is a triage step that supports the assessment of many techniques rather than firing on one, so T1071 is cited here as the C2 technique this enrichment helps an analyst investigate, not as something the tool alerts on. That distinction is deliberate and it matters when briefing a verdict.

IP-Commander runs four sequential checks: geolocation (country, city, ISP, ASN from ip-api.com), abuse reputation (AbuseIPDB confidence score 0–100 and total report count, the single most decision-relevant data point), reverse DNS (PTR resolution via Python's socket library, where naming patterns like dns.google confirm legitimate infrastructure), and a consolidated LOW/MODERATE/HIGH RISK verdict written to disk.

Against `8.8.8.8`, every module corroborated the others: Google-owned infrastructure, a `0/100` abuse score despite substantial community reporting volume (116 reports, meaning AbuseIPDB has plenty of historical data on this IP, none of it indicating abuse), and a clean reverse DNS resolution to `dns.google`. Three independent data sources, one consistent picture.

## Audit Target

| Attribute | Value |
| --- | --- |
| Target IP | `8.8.8.8` |
| Audit type | Passive enrichment, known-good infrastructure used as validation target |
| Tool | `ip-commander.py`, custom Python, built from scratch |
| Data sources | `ip-api.com` (geolocation), AbuseIPDB API (abuse reputation), Python `socket` (reverse DNS) |
| Environment | Kali Linux, Python 3.13, `requests` |

## Scope and Authorization

This audit was conducted against `8.8.8.8`, Google's public DNS resolver, a well-known, publicly documented IP address used here for tool validation. IP-Commander performs only passive, read-only lookups: a geolocation API query, an AbuseIPDB reputation check, and a standard reverse DNS resolution. No active scanning, exploitation, or unauthorized access of any kind is performed against the target IP.

This tool is intended for enriching IP addresses already observed in authorized log sources (SIEM alerts, firewall logs, IDS events), not for scanning arbitrary infrastructure without authorization.

## Investigation Methodology

### 1. API Key Provisioning and Secrets Handling

Registered for a free AbuseIPDB account and generated an API key. The key was stored as an environment variable (`ABUSEIPDB_KEY`) in the shell configuration file rather than hardcoded into the script, a deliberate production security practice. During setup, a key was briefly exposed in a terminal screenshot; it was immediately revoked and regenerated before any further use, and the replacement key was verified as configured without ever displaying its value again.

*Screenshot: `02_api_key_configured.png`*

**SOC Observation**

Secrets management discipline matters as much in a home lab as in production. A leaked API key, even a free-tier one, should be treated as compromised and rotated immediately, not left in place because it is just a lab. The habit only becomes automatic when the stakes are real if it was already automatic when they weren't.

### 2. Tool Foundation: IP Validation

Built the script skeleton with argument parsing (`-i` for IP address, `-o` for output file) and an IP format validator that confirms the input is a syntactically valid IPv4 address before any network request is made.

### 3. Module 1: Geolocation

Queried `ip-api.com` (free, no API key required) for country, city, ISP, and organization/ASN data tied to the target IP.

*Screenshot: `03a_geolocation_module.png`*

**Findings for `8.8.8.8`:**

| Field | Value |
| --- | --- |
| Country | United States |
| City | Ashburn |
| ISP | Google LLC |
| ASN/Org | Google Public DNS |

### 4. Module 2: Abuse Reputation

Queried the AbuseIPDB API using the stored key, requesting abuse data from the last 90 days. The module interprets the returned confidence score into a three-tier verdict: LOW RISK (under 25), MODERATE RISK (25–74), HIGH RISK (75 and above).

*Screenshot: `03b_abuse_reputation_module.png`*

**Findings for `8.8.8.8`:**

| Field | Value |
| --- | --- |
| Abuse confidence score | 0 / 100 |
| Total reports | 116 |
| Last reported | 2026-06-26 |
| Verdict | LOW RISK |

**Analyst note**

The combination of 116 total reports and a 0/100 confidence score is itself the finding. It confirms AbuseIPDB has substantial historical visibility into this IP and consistently finds nothing malicious, rather than simply lacking data. A 0/100 score with zero reports would mean unknown, not confirmed clean. Reading a score without reading the volume behind it is how an analyst mistakes silence for safety.

### 5. Module 3: Reverse DNS Lookup

Used Python's built-in `socket.gethostbyaddr()` to resolve the IP back to a PTR (reverse DNS) record.

*Screenshot: `03c_reverse_dns_and_report.png`*

**Finding for `8.8.8.8`:** Hostname resolved to `dns.google`, a clean, self-identifying hostname consistent with legitimate Google infrastructure.

### 6. Module 4: Verdict and Report Generation

Consolidated all three modules into a single structured report with an overall risk verdict, written to `output/8.8.8.8_report.txt`.

## Threat Intelligence Findings (Consolidated)

| Data Source | Finding | Defender Significance |
| --- | --- | --- |
| Geolocation | United States, Ashburn — Google LLC | Confirms infrastructure ownership and physical hosting region |
| Abuse Reputation | 0/100 score, 116 historical reports | High-confidence clean verdict, extensive data, no abuse pattern |
| Reverse DNS | `dns.google` | Self-identifying hostname corroborates the geolocation finding |
| Overall Verdict | LOW RISK | All three independent sources agree, safe to deprioritize in triage |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
| --- | --- | --- | --- |
| Command and Control | Application Layer Protocol | T1071 | The C2 technique this enrichment supports investigating. Geolocation, abuse history, and reverse DNS are used to assess whether an IP observed in protocol-layer traffic is masking malicious command-and-control, rather than to detect the traffic itself. Enrichment is a triage input to a T1071 assessment, not a detection of it. |

## Findings

- All three independent data sources (geolocation, abuse reputation, reverse DNS) corroborated each other for `8.8.8.8`, producing a high-confidence LOW RISK verdict.
- The abuse reputation check returned 116 historical reports alongside a 0/100 confidence score, demonstrating that a clean verdict is strongest when backed by substantial reporting volume, not the absence of data.
- The tool's three-tier verdict system (LOW / MODERATE / HIGH RISK) maps directly to standard SOC triage priority: HIGH RISK IPs warrant immediate escalation, LOW RISK IPs can be deprioritized without further manual lookup.
- Secrets handling was tested under real conditions: an API key was exposed during setup, immediately revoked, and replaced, demonstrating the rotation discipline expected in production environments.

## Response

For a SOC team integrating IP enrichment into triage workflow:

1. Run IP-Commander against every unfamiliar IP in SIEM alerts before manual investigation, automating the first triage pass.
2. Escalate immediately on any HIGH RISK verdict (abuse score 75 or above), cross-referencing the IP against firewall and proxy logs for matching traffic.
3. Treat LOW RISK verdicts with substantial report history as high-confidence, and LOW RISK verdicts with zero report history as unknown rather than safe, the distinction affects how much additional scrutiny is warranted.
4. Rotate any API key that is ever exposed, even briefly and even in a non-production environment, treating exposure as compromise regardless of context.
5. Extend the tool to batch-process IP lists extracted from log exports, enabling enrichment of dozens of IOCs in a single run rather than one at a time.

## The SOC Angle

The most valuable lesson from this project happened before a single line of OSINT code ran: the API key exposure during setup.

It would have been easy to treat a free-tier lab key as low-stakes and leave it in place. The correct response, revoke immediately, regenerate, verify the replacement without ever displaying it again, is the same discipline a production incident would demand for a real credential leak. Building good secrets hygiene into a home-lab project is what makes the habit automatic when the stakes are real.

On the technical side, the abuse module taught the subtler lesson: a risk score alone is incomplete without its supporting evidence. A 0/100 backed by 116 reports is a fundamentally different finding than a 0/100 backed by zero reports, one is confirmed clean, the other is merely unverified. Designing the tool to surface both numbers, not just the score, is what makes the output usable for a real decision rather than a false sense of certainty. That instinct, refusing to trust a number without the volume behind it, is the same one that separates a good triage verdict from a lucky one.

## What This Demonstrates

Building a four-module Python threat-intelligence enrichment tool from scratch, integrating two external APIs (ip-api.com, AbuseIPDB) and a native DNS resolution library.

Implementing secure secrets handling with environment variables, and practicing real credential rotation after an accidental exposure.

Framing MITRE T1071 honestly, as the technique an enrichment workflow supports assessing rather than one the tool detects.

Designing a tiered risk verdict system (LOW/MODERATE/HIGH) that maps tool output directly to analyst escalation priority.

Interpreting threat-intelligence data with appropriate nuance, recognizing that report volume changes the meaning of a confidence score.

## Repository Structure

```
Project-05-IPCommander/
├── README.md
├── scripts/
│   └── ip-commander.py
├── output/
│   └── 8.8.8.8_report.txt
├── reports/
└── screenshots/
    ├── 01_folder_structure.png
    ├── 02_api_key_configured.png
    ├── 03a_geolocation_module.png
    ├── 03b_abuse_reputation_module.png
    └── 03c_reverse_dns_and_report.png
```

## Conclusion

IP-Commander demonstrates the threat-intelligence enrichment pipeline a SOC analyst runs every time an unfamiliar IP surfaces in the logs, built from scratch, validated against a known-clean target, and producing a single corroborated verdict from three independent data sources. The 0/100 abuse score backed by 116 historical reports, the matching geolocation, and the self-identifying reverse DNS hostname all point the same direction, which is exactly what a defender wants to see before deprioritizing an alert. Automating this enrichment turns a five-minute manual lookup into a five-second decision, and the secrets-handling discipline practiced along the way is the same standard that protects production credentials when the stakes are real.

---

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=flat&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

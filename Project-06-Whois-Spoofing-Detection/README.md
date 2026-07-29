# Whois-Guard: Domain Spoofing Detection (MITRE T1566)

> Built a custom Python tool that generates typosquat variants of a legitimate domain, queries WHOIS for each, and flags recently registered lookalikes as phishing infrastructure, turning the attacker's domain registration pattern into a defender's early-warning signal.

26 variants checked, 25 registered, and the finding that matters is not a count, it is a registrar. 14 of those lookalikes belong to Google's own brand-protection registrar, which means the single domain that does not, `google-login.com` via Alibaba Cloud, is the one worth a defender's attention. WHOIS sees the phishing infrastructure before the first email is sent.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Phishing infrastructure detection, Python |
| Tool | Whois-Guard, four modules, built from scratch |
| Validation Target | google.com |
| Variants / Registered | 26 checked, 25 registered (96%) |
| Key Signal | Registrar identity, 14 held by MarkMonitor |
| Standout Finding | google-login.com, 407 days, Alibaba Cloud |
| Environment | Kali, Python 3.13, python-whois |
| MITRE | T1566, detected at registration stage |

## What This Is

Before a phishing email is sent, a domain is registered. That registration is the earliest detectable signal in the phishing attack chain, and it is publicly visible to anyone who knows where to look. An attacker registers `google-login.com` today; tomorrow it appears in phishing emails. But today, right now, WHOIS already knows it exists.

Whois-Guard was built to surface that signal proactively. Given a legitimate domain, it generates every common typosquat variant an attacker might register, character substitutions, omissions, transpositions, and phishing suffixes, then queries public WHOIS for each. Any variant that is registered and was created recently gets flagged as HIGH RISK phishing infrastructure.

## Executive Summary

MITRE ATT&CK T1566 (Phishing) describes adversaries sending malicious messages to trick users into revealing credentials, clicking malicious links, or opening malicious attachments. Domain spoofing is one of the most reliable enablers: a domain that looks almost identical to a trusted brand removes the visual cue most users rely on to judge legitimacy.

Whois-Guard operationalizes phishing-domain detection through four modules: a typosquat variant generator (character substitution, omission, transposition, suffix addition, TLD variation), a WHOIS lookup (creation date, registrar, registration age), risk scoring (HIGH RISK if created within a configurable window, default 180 days; MODERATE if older), and a report generator with a summary table and analyst action notes.

Against `google.com`, 25 of 26 variants were registered. Zero met the HIGH RISK threshold, because Google's brand-protection program registers lookalike domains defensively before attackers can. That result is not a null finding, it is the lesson: the scan surfaced the registrar pattern that makes WHOIS analysis actionable in practice.

## Audit Target

| Attribute | Value |
| --- | --- |
| Target domain | `google.com` |
| Audit type | Passive WHOIS enumeration against a well-known domain for tool validation |
| Variants generated | 26 |
| Registered | 25 (96%) |
| HIGH RISK | 0 |
| MODERATE RISK | 25 |
| Unregistered | 1 |
| Tool | `whois-guard.py`, custom Python, built from scratch |
| Environment | Kali Linux, Python 3.13, `python-whois` library |

## Scope and Authorization

This audit queries only the public WHOIS registration database, information publicly available to anyone. No authentication, network scanning, exploitation, or contact with the audited domains was performed. WHOIS lookups were rate-limited (0.5 second pause between requests) to avoid triggering query limits on WHOIS servers.

This tool is intended for auditing domains you own or are authorized to protect, and for investigating suspicious domains observed in phishing emails, proxy logs, or threat intelligence feeds. The rate-limiting is not incidental, it is the difference between querying shared public infrastructure responsibly and abusing it.

## Investigation Methodology

### 1. Environment Setup and Dependency Installation

Installed `python-whois`, the only external library required beyond the Python standard library. Verified Python 3.13, pip 26, and the library import before writing any tool code.

*Screenshot: `02_python_environment.png`*

### 2. Module 1: Typosquat Variant Generation

Built the variant generator to cover the attack patterns most commonly used in domain spoofing campaigns.

**Character substitution** replaces visually similar characters: `o` becomes `0`, `i` becomes `1`, `s` becomes `5`. The attacker relies on users not noticing the swap at a glance.

**Character omission** drops a single letter, `google.com` becomes `gogle.com`. At reading speed, a missing character is easy to miss.

**Character transposition** swaps adjacent characters, `google.com` becomes `googel.com`. The brain reads familiar words by shape, not letter by letter, so transpositions are particularly effective against inattentive readers.

**Suffix addition** appends common phishing terms: `google-login.com`, `google-support.com`, `google-verify.com`. These exploit the legitimate practice of companies using subdomain-style naming for services.

**TLD variation** keeps the name identical but changes the top-level domain: `google.net`, `google.org`, `google.co`. Less convincing to a careful reader but effective in bulk phishing campaigns.

*Screenshot: `03a_scan_running.png`*

### 3. Modules 2 and 3: WHOIS Lookup and Risk Scoring

Ran WHOIS queries against all 26 generated variants. Each result was classified by registration age against the 180-day threshold.

*Screenshots: `03b_scan_results.png`, `03c_scan_complete.png`*

**Key finding, the MarkMonitor pattern:**

| Registrar | Count | Interpretation |
| --- | --- | --- |
| MarkMonitor, Inc. | 14 | Google's own brand protection registrar, defensive registrations |
| GoDaddy.com, LLC | 3 | Third-party, potential squatter or legacy registration |
| NAMECHEAP INC | 1 | Third-party, requires investigation |
| Alibaba Cloud / HiChina | 1 | Third-party, `google-login.com`, most suspicious finding |
| Other | 6 | Mixed third-party registrars |

MarkMonitor is Google's designated brand-protection registrar. Any lookalike registered through MarkMonitor is almost certainly a defensive registration by Google itself; any lookalike registered through a different registrar is a potential threat that warrants investigation. That single distinction is what converts a wall of 25 scary-looking domains into a shortlist of one.

### 4. Module 4: Report Generation

Consolidated all findings into `output/google_spoof_scan.txt` with a scan summary, full moderate-risk domain list, and analyst action notes.

## Findings

### Scan Summary

| Metric | Value |
| --- | --- |
| Variants checked | 26 |
| Registered | 25 (96%) |
| HIGH RISK (within 180 days) | 0 |
| MODERATE RISK (registered, older) | 25 |
| Unregistered | 1 |

### Most Significant Finding

`google-login.com`, registered 407 days ago via Alibaba Cloud Computing / HiChina. This is the only registered lookalike not held by MarkMonitor or a clearly identifiable brand-protection entity. The word "login" in a lookalike domain name is a standard phishing-infrastructure naming pattern. While it falls outside the 180-day HIGH RISK window, it would warrant immediate investigation in a real corporate audit, the window catches the freshest threats, but analyst judgment catches the ones that age past it.

### Notable Registrar Observations

- `gogle.com`, `googel.com`, `googl.com`, `ogogle.com`, `goolge.com`: all held by MarkMonitor. Google registered its own typosquats years ago as a defensive measure.
- `9oogle.com`: held by Gname.com Pte. Ltd., registered 970 days ago. Not MarkMonitor, not Google, unknown purpose.
- `goo9le.com`: held by Namecheap, registered 1612 days ago. Third-party squatter.
- `googl3.com`: the sole unregistered domain in the set.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
| --- | --- | --- | --- |
| Initial Access | Phishing | T1566 | Domain spoofing enables phishing by registering lookalike domains that deceive users into trusting malicious links or credential-harvesting pages. Whois-Guard detects this infrastructure at the registration stage, before any phishing email is sent. |

## Findings Summary

- 25 of 26 generated variants are registered. For a high-profile domain like Google, near-total coverage is expected due to aggressive defensive registration and historical squatting.
- MarkMonitor Inc. holds the majority of registered variants, confirming Google's proactive brand-protection program. This registrar pattern is the primary signal for distinguishing defensive registrations from threats.
- `google-login.com` is the most suspicious finding, registered via Alibaba Cloud, outside the MarkMonitor umbrella, using a phishing-infrastructure naming pattern.
- Zero HIGH RISK domains within the 180-day threshold, consistent with Google's brand-protection maturity. A smaller organization running this same tool against its own domain would expect a very different result.
- One variant remains unregistered (`googl3.com`), a gap in Google's defensive coverage.

## Response

For an organization running Whois-Guard against its own domain:

1. Block all HIGH RISK domains immediately at the email gateway, web proxy, and DNS layer. A domain registered yesterday that looks like yours is active or pre-campaign phishing infrastructure.
2. Investigate MODERATE RISK domains held by unknown registrars, especially those using phishing-associated naming patterns such as "login", "verify", "secure", or "support".
3. Report confirmed phishing domains to the registrar via their abuse channel and to threat-intelligence platforms (PhishTank, APWG).
4. Register your own typosquat variants defensively if budget allows. This is what Google does via MarkMonitor, and it eliminates the attack surface entirely for the registered variants.
5. Run Whois-Guard on a recurring schedule, monthly at minimum. Attackers register domains close to campaign launch dates, so the HIGH RISK window catches the most dangerous registrations before they are activated.

## The SOC Angle

The most important lesson from this scan was not a HIGH RISK flag, it was the MarkMonitor pattern.

Without understanding what that registrar means, an analyst looking at 25 registered lookalike domains might panic. With that context, most of those registrations are immediately deprioritized, and the remaining third-party registrations, especially `google-login.com` via Alibaba Cloud, become the actual signal.

This is the core skill WHOIS analysis teaches: the same raw data means completely different things depending on context. A registered lookalike domain is not automatically a threat. Who registered it, when, and through which registrar are the three questions that turn a list of domains into an actionable finding. A tool that surfaces all three and lets the analyst apply judgment is exactly what threat-intelligence tooling should do, the tool narrows, the analyst decides.

## What This Demonstrates

Building a four-module Python domain-spoofing detection tool from scratch, covering variant generation, WHOIS enrichment, risk scoring, and report output.

Knowing the four typosquat attack patterns (substitution, omission, transposition, suffix addition) that make lookalike domains effective phishing infrastructure.

Reading WHOIS registration data as a defensive signal, and specifically the role of brand-protection registrars like MarkMonitor in separating defensive registrations from threats.

Interpreting tool output with analyst judgment, recognizing that a finding's context (registrar, age, naming pattern) determines its actual risk.

Implementing WHOIS rate-limiting in the tool itself, demonstrating responsible query behavior against shared public infrastructure.

## Repository Structure

```
Project-06-WhoisGuard/
├── README.md
├── scripts/
│   └── whois-guard.py
├── output/
│   └── google_spoof_scan.txt
├── reports/
└── screenshots/
    ├── 01_folder_structure.png
    ├── 02_python_environment.png
    ├── 03a_scan_running.png
    ├── 03b_scan_results.png
    └── 03c_scan_complete.png
```

## Conclusion

Whois-Guard demonstrates domain spoofing detection at the earliest possible stage, before the phishing email is sent, before the user clicks, before any alert fires in the SIEM. A domain registration is the first public artifact an attacker creates, and WHOIS makes it visible to any defender who looks. The Google scan validated the tool's core logic and revealed the registrar-pattern analysis that separates useful WHOIS findings from noise. For a smaller organization without Google's brand-protection resources, the same scan against their own domain would surface real threats rather than defensive registrations. That is the point: the tool works the same way regardless of the target, and the analyst's job is to interpret what it finds.

---

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=flat&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

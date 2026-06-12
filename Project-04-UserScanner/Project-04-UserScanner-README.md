# Project 04 — User-Scanner: Email & Username OSINT Tool (MITRE T1589)

> Built a custom Python tool that takes a single email address and produces a complete identity reconnaissance profile — mail server fingerprint, derived username platform presence, and targeted dork queries — the same audit an adversary runs before crafting a targeted attack.

---

## Audit Summary

A single email address is not just a way to contact someone. It is a reconnaissance starting point.

From `james@gmail.com`, an attacker extracts two things immediately: the username (`james`) and the domain (`gmail.com`). The domain tells them which mail provider handles the account. The username unlocks a platform enumeration sweep. The email address itself feeds directly into breach databases and paste site queries.

**User-Scanner** was built to run that audit from the defender's side first. Given an email address, it executes a four-module pipeline: validate the address, look up the domain's mail infrastructure, check the derived username across eight platforms, and generate ten targeted dork queries covering breach exposure, credential leakage, and document disclosure.

Against `james@gmail.com`, the tool confirmed **6 out of 8 platforms** in under a minute — GitHub, GitLab, Reddit, Dev.to, Medium, and Keybase — and fingerprinted the mail provider as **Google Workspace / Gmail** with 5 active MX records. All results produced passively, without a single authenticated request.

---

## Executive Summary

**MITRE ATT&CK T1589 (Gather Victim Identity Information)** describes the phase where adversaries enumerate publicly available details about targets before attacking. An email address is one of the richest single inputs an attacker can possess — it chains directly into domain intelligence, username enumeration, and breach data in one lookup sequence.

User-Scanner operationalizes this defensively through four modules:

1. **Email Validation** — confirms the address matches a valid format before any network activity begins.
2. **Domain Analysis (MX Records)** — resolves the domain's mail exchange records and fingerprints the email provider. Knowing the provider tells a defender what email security controls are (or aren't) in place.
3. **Platform Presence Checker** — extracts the username from the email and checks for confirmed presence across eight platforms.
4. **Dork Generator** — produces ten targeted queries covering direct email exposure, paste sites, credential mentions, API key leakage, and domain-level staff enumeration.

The complete pipeline runs in seconds and outputs a structured plain-text report suitable for analyst review and evidence documentation.

---

## Audit Target

| Attribute | Value |
|---|---|
| Target email | `james@gmail.com` |
| Derived username | `james` |
| Domain | `gmail.com` |
| Audit type | Passive OSINT — authorized test against generic address |
| Platforms checked | 8 |
| Profiles confirmed | 6 |
| Tool | `user-scanner.py` — custom Python, built from scratch |
| Environment | Kali Linux, Python 3.13, `requests`, `dnspython` |

---

## Scope and Authorization

This audit was conducted against a generic test email address (`james@gmail.com`) for demonstration purposes. User-Scanner performs only passive, read-only HTTP requests and DNS queries against publicly accessible resources. No authentication, brute-forcing, or exploitation was performed.

Running this tool against email addresses you do not own or have explicit authorization to audit may violate platform terms of service or applicable law.

---

## Investigation Methodology

### 1. Tool Foundation — Email Validation and Extraction
Built the script skeleton with argument parsing (`-e` for email, `-o` for output file), a regex-based email validator, and a parser that splits the address into username and domain components. The validator rejects malformed input immediately — the tool never makes a network request against an invalid address.

*Screenshot: `03_foundation.png`*

**Analyst note:** Input validation before any network activity is both an engineering best practice and an operational discipline — a tool that crashes on bad input wastes analyst time and may generate noise in logs.

### 2. Module 1 — Email Domain Analysis (MX Records)
Used `dnspython` to resolve the domain's MX records, sorted them by priority, and fingerprinted the email provider against a known-provider lookup table.

*Screenshots: `04a_module1_mx_lookup.png`*

**Findings for `gmail.com`:**

| Priority | MX Host |
|---|---|
| 5 | `gmail-smtp-in.l.google.com` |
| 10 | `alt1.gmail-smtp-in.l.google.com` |
| 20 | `alt2.gmail-smtp-in.l.google.com` |
| 30 | `alt3.gmail-smtp-in.l.google.com` |
| 40 | `alt4.gmail-smtp-in.l.google.com` |

**Provider fingerprint:** Google Workspace / Gmail

**SOC Observation:** MX records reveal which provider handles a target's email. For a corporate domain (e.g. `nexuscorp.com`), an attacker who finds `mimecast.com` or `proofpoint.com` in the MX records knows the organization is running an email security gateway — and can adjust their phishing approach accordingly. A defender who runs this check first knows what their own MX fingerprint discloses.

### 3. Module 2 — Platform Presence (Derived Username)
Extracted `james` from the email address and ran HTTP presence checks across eight platforms, interpreting each response code as a distinct finding.

*Screenshot: `04b_platform_presence.png`*

**Findings:**

| Platform | Result | URL |
|---|---|---|
| GitHub | **FOUND** | https://github.com/james |
| GitLab | **FOUND** | https://gitlab.com/james |
| Reddit | **FOUND** | https://www.reddit.com/user/james |
| Dev.to | **FOUND** | https://dev.to/james |
| Medium | **FOUND** | https://medium.com/@james |
| Keybase | **FOUND** | https://keybase.io/james |
| HackerNews | NOT FOUND | — |
| TryHackMe | NOT FOUND | — |

**6 out of 8 platforms confirmed.**

### 4. Module 3 — Targeted Dork Generator
Generated ten targeted queries combining the full email address, derived username, and domain — covering direct email exposure, paste sites, credential mentions, API key leakage, and domain-level staff enumeration.

*Screenshot: `04c_dorks_and_report.png`*

**Highest-priority dorks for manual execution:**
- `[04]` `"james@gmail.com" intext:"password" OR intext:"credentials"` — credential exposure
- `[05]` `"james@gmail.com" "API key" OR "access token" OR "secret"` — secret leakage
- `[02]` `"james@gmail.com" site:pastebin.com` — paste dump check

### 5. Module 4 — Report Generation
Consolidated all findings into a structured plain-text report written to `output/james_gmail_scan.txt`. The report includes domain analysis, MX records, platform summary, confirmed profiles, dork queries, and analyst notes.

*Screenshots: `05a_output_file.png`, `05b_output_file.png`*

---

## Digital Footprint Findings (Exposed Indicators)

| Category | Finding | Attacker Intelligence Value |
|---|---|---|
| Email domain | `gmail.com` | Google Workspace — known provider, known phishing templates |
| MX records | 5 records confirmed | Redundant infrastructure — no single point of failure |
| Platform — GitHub | `github.com/james` | Code repos, commit history, potential email in commits |
| Platform — GitLab | `gitlab.com/james` | Additional code repositories |
| Platform — Reddit | `reddit.com/user/james` | Post history, communities, interests |
| Platform — Dev.to | `dev.to/james` | Technical articles, stack preferences |
| Platform — Medium | `medium.com/@james` | Writing history, professional interests |
| Platform — Keybase | `keybase.io/james` | Cryptographic identity, linked accounts |

**Important analyst caveat:** The username `james` is extremely common. The six confirmed platform profiles may represent different individuals rather than a single person. For a corporate audit, a more specific username (e.g. `john.smith` from `john.smith@nexuscorp.com`) would produce higher-confidence correlation.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
|---|---|---|---|
| Reconnaissance | Gather Victim Identity Information | T1589 | Passive enumeration of a target email address — extracting username, domain, mail infrastructure, platform presence, and credential exposure indicators before any direct network contact. |

---

## SOC Analyst Findings

- Target email `james@gmail.com` maps to provider **Google Workspace / Gmail** with 5 active MX records — fully redundant mail infrastructure confirmed.
- Derived username `james` returned **6 confirmed platform profiles** across code hosting, social, and developer platforms.
- GitHub and GitLab confirmed — code repositories publicly accessible, potentially exposing commit history, email addresses embedded in commits, and technology stack.
- Keybase confirmed — cryptographic identity platform that may link to additional verified accounts.
- Dork queries [04] and [05] (credential and API key mentions) are the highest-priority items for manual follow-up — any results indicate active secret exposure.
- Username `james` is non-unique — profile matches require manual verification to confirm they belong to the same individual as the target email.

---

## SOC Analyst Response

For an organization auditing employee email addresses:

1. **Run Module 1 against corporate domains** — know your own MX fingerprint before an attacker does. If your domain exposes no security gateway (Mimecast, Proofpoint), that is a hardening gap.
2. **Manually execute dork queries [04] and [05]** for each corporate email address scanned. Any results require immediate credential rotation and secret revocation.
3. **Review confirmed platform profiles** — GitHub and GitLab in particular. Check commit history for accidentally committed credentials, API keys, or internal hostnames.
4. **Flag username-to-email correlations** for corporate addresses — a specific username like `john.smith` with 6 confirmed platforms is a high-value intelligence asset for a spear-phishing campaign.
5. **Run User-Scanner quarterly** against key employee and service-account email addresses — exposure changes as accounts are created and content is published.

---

## Analyst Insight

The most instructive output from this scan was not the 6 confirmed platforms — it was the MX fingerprint. Five redundant MX records pointing to Google infrastructure tells an attacker two things: the target uses Gmail (which determines which social engineering angles work), and the infrastructure is resilient (no single-point takedown). For a corporate domain, the MX fingerprint tells an attacker whether the organization has a security gateway in front of their mail. That single DNS query shapes the entire phishing approach before a single email is drafted.

The username caveat matters too. `james` is so common that the six confirmed profiles almost certainly do not all belong to the same person. A real-world scan uses a specific corporate username — `james.williams` or `j.williams` — where profile correlation is defensible. Tool output always needs analyst judgment. Automation surfaces the data; the analyst determines what it means.

---

## Learning Outcome

- Built a four-module Python OSINT pipeline from scratch that takes a single email address and produces a complete reconnaissance profile.
- Implemented DNS MX record resolution using `dnspython` and translated raw DNS responses into actionable defender intelligence (provider fingerprinting).
- Practiced the T1589 attack chain — email → username extraction → platform enumeration → dork generation — from the defender's perspective.
- Applied analyst judgment to raw tool output: 6 confirmed profiles on a generic username require verification before conclusions are drawn.
- Produced structured, file-based report output suitable for evidence documentation and case management.

---

## Repository Structure

```
Project-04-UserScanner/
├── README.md
├── scripts/
│   └── user-scanner.py
├── output/
│   └── james_gmail_scan.txt
├── reports/
└── screenshots/
    ├── 01_folder_structure.png
    ├── 02_python_environment.png
    ├── 03_foundation.png
    ├── 04a_module1_mx_lookup.png
    ├── 04b_platform_presence.png
    ├── 04c_dorks_and_report.png
    ├── 05a_output_file.png
    └── 05b_output_file.png
```

---

## Conclusion

User-Scanner demonstrates the full T1589 reconnaissance pipeline — from a single email address to a complete identity profile — built from scratch, run passively, and interpreted through an analyst's lens. The MX fingerprint shows what a target's email infrastructure reveals before any message is sent. The platform sweep shows how a username extracted from an email cascades into public profile discovery across six platforms. The dork generator produces the queries an attacker would run to find credential exposure and API key leakage. Running this audit first — before the attacker does — is the entire point. The cheapest intelligence-gathering step in an adversary's playbook is also the one a defender can close in an afternoon.

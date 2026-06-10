# Project 03 Tookie-OSINT: Digital Footprint Auditor (MITRE T1589)

> Built a custom Python OSINT tool from scratch that maps a target's public digital footprint across platforms the same identity enumeration an adversary performs before attacking, run proactively by the defender.

---

## Audit Summary

Before an attacker sends a single packet to your network, they know who works there, what platforms those people use, what they post publicly, and what their technical interests reveal about the organisation's stack.

**MITRE ATT&CK T1589 (Gather Victim Identity Information)** describes this phase. It is passive, free, and leaves no trace on the victim's systems. If a defender has not audited their own identity exposure, the attacker already has an information advantage.

To operationalize this defensively, **Tookie-OSINT** was built from scratch: a three-module Python tool that takes a username, checks for confirmed presence across eight platforms, generates targeted Google dork queries for deeper manual research, and produces a structured digital footprint report. The tool was run against the analyst's own public username `WiLL75G` as an authorized self-audit.

The findings were immediate: three confirmed public profiles (GitHub, Reddit, HackerNews), each exposing a different category of intelligence to any adversary who looks.

---

## Executive Summary

Identity reconnaissance is among the cheapest steps in an attacker's playbook. A username checked against eight platforms takes seconds. The platforms themselves do the work they serve public profile pages to anyone who requests them.

Tookie-OSINT was built to turn this into a defender's tool. Given a target username, it runs three sequential modules:

1. **Platform Presence Checker** sends HTTP requests to each platform's public profile URL and interprets the response code. `200 OK` is a confirmed profile. `404` is a confirmed absence. `403` is access-restricted, not absent. `429` is rate-limited the profile may exist but the platform blocked the probe. The distinction matters.
2. **Google Dork Generator** produces ten targeted search queries covering the username across platforms, document types, credential exposure, and API key leakage.
3. **Report Generator** consolidates all findings into a structured plain-text report saved to disk, suitable for analyst review and evidence documentation.

Against `WiLL75G`, the tool confirmed three public profiles with meaningful attacker value across code exposure, post history, and technical commentary and correctly flagged a rate-limited response from TryHackMe as inconclusive rather than absent.

---

## Audit Target

| Attribute | Value |
|---|---|
| Target username | `WiLL75G` |
| Audit type | Passive OSINT authorized self-audit |
| Platforms checked | 8 |
| Profiles confirmed | 3 |
| Tool | `tookie.py` custom Python, built from scratch |
| Environment | Kali Linux, Python 3, `requests` library |

---

## Scope and Authorization

This audit was conducted against the analyst's own public username. All checks used only HTTP GET requests to publicly accessible profile URLs the same requests any browser makes when visiting a profile page. No authentication, exploitation, brute-forcing, or scraping of protected content was performed.

Running this tool against usernames you do not own or have explicit authorization to audit is outside the scope of this project and may violate platform terms of service or applicable law.

---

## Investigation Methodology

### 1. Environment and Tool Setup
Verified Python 3 and the `requests` library, created the project folder structure, and confirmed the development environment on Kali Linux.

*Screenshot: `02_python_environment.png`*

### 2. Built the Tool Foundation (tookie.py skeleton)
Authored the script header, argument parser (`-u` for username, `-o` for output file), and entry point. Ran a smoke test to confirm the banner and INFO block rendered correctly before adding any OSINT logic.

*Screenshot: `03_tookie_foundation.png`*

**Analyst note:** Building a clean foundation before adding modules enforces the discipline of separating concerns each module does one thing and returns structured data to `main()`. This makes the tool easier to extend and easier to audit.

### 3. Module 1 Platform Presence Checker
Added HTTP GET checks against eight platforms using an honest User-Agent and a 6-second timeout. Each response code is interpreted and classified:

| HTTP Code | Classification | Analyst Meaning |
|---|---|---|
| 200 | FOUND | Profile confirmed and publicly accessible |
| 404 | NOT FOUND | Profile does not exist on this platform |
| 403 | NOT FOUND (restricted) | Access denied may exist but not publicly accessible |
| 429 | TIMEOUT/ERROR | Rate-limited existence inconclusive, manual check required |

*Screenshot: `06a_module1_platform_results.png`*

**Findings:**

| Platform | Result | HTTP Code |
|---|---|---|
| GitHub | **FOUND** | 200 |
| Reddit | **FOUND** | 200 |
| HackerNews | **FOUND** | 200 |
| TryHackMe | Inconclusive | 429 (rate-limited) |
| GitLab | Not found | 403 |
| Medium | Not found | 403 |
| Keybase | Not found | 404 |
| Dev.to | Not found | 404 |

### 4. Module 2 Google Dork Generator
Added generation of ten targeted dork queries covering platform presence, document exposure, paste sites, credential mentions, and API key leakage all tied to the target username.

*Screenshot: `06b_module2_dork_queries.png`*

**Analyst note:** The dork generator is deliberately passive it produces queries for manual execution rather than automating searches, giving the analyst full control over what gets queried and when. Dorks [08]–[10] (`intext:"password"`, `"API key"`, `"access token"`) are the highest-value from a defensive standpoint: if they return results, there is a credential or secret exposure that requires immediate action.

### 5. Module 3 Report Generator
Added a structured report that consolidates platform results, confirmed profile URLs, dork queries, and analyst notes into a plain-text file written to `output/`. The `-o` flag triggers the file write; without it the report prints to terminal only.

*Screenshots: `06c_module3_footprint_report.png`, `07a_output_file.png`, `07b_output_file.png`*

---

## Digital Footprint Findings (Exposed Indicators)

| Platform | Confirmed URL | Attacker Intelligence Value |
|---|---|---|
| GitHub | `https://github.com/WiLL75G` | Repository names, commit history, programming languages, potential email address in commits |
| Reddit | `https://www.reddit.com/user/WiLL75G` | Post and comment history, subreddit memberships, interests, account age |
| HackerNews | `https://news.ycombinator.com/user?id=WiLL75G` | Technical commentary, interests, professional context |

**TryHackMe (429 inconclusive):** The platform returned a rate-limit response rather than a 404. The profile may exist. Manual verification required.

**Generated dork queries:** 10 queries across platform presence, document exposure (`filetype:pdf`, `filetype:doc`), paste sites, credential mentions, and API key searches.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
|---|---|---|---|
| Reconnaissance | Gather Victim Identity Information | T1589 | Passive enumeration of a target username's public presence across platforms the identity mapping an adversary performs before any direct network interaction. |

---

## SOC Analyst Findings

- Three public profiles confirmed: `GitHub`, `Reddit`, `HackerNews` each exposing a distinct intelligence category (code, social, technical commentary).
- GitHub exposes the most operationally sensitive data: repository names reveal technologies in use; commit history may expose email addresses; public repos may contain secrets committed accidentally.
- TryHackMe returned `429` (rate-limited), not `404` the profile may exist. Tool correctly classified this as inconclusive rather than absent. Manual verification recommended.
- No credential or API key exposure detected in this run dork queries [08]–[10] should be run manually to confirm.
- Username `WiLL75G` is consistent across confirmed platforms an attacker correlating identity across platforms has a high-confidence match.

---

## SOC Analyst Response

For an organization auditing employee or service-account usernames:

1. **Review GitHub email visibility settings** commit history can expose email addresses even when the profile hides them.
2. **Audit Reddit and HackerNews post history** for sensitive organizational information, technology disclosures, or security questions.
3. **Manually verify any `429` responses** rate-limited platforms require a browser check to confirm presence or absence.
4. **Run the credential dork queries** (`intext:"password"`, `"API key"`, `"access token"`) manually and investigate any results immediately.
5. **Run Tookie-OSINT on a recurring schedule** against critical usernames exposure changes as users create new accounts, post new content, or commit new code.

---

## Analyst Insight

The most instructive moment in this audit was the TryHackMe `429` response. A less careful tool or a less careful analyst would classify that as "not found" and move on. It is not not found. It is rate-limited, which means the platform detected automated querying and refused to answer. The profile may exist. That distinction is the difference between a closed gap and an open one that was simply mislabeled.

It is also a reminder that tool output requires interpretation. HTTP response codes are not binary. `403` is not the same as `404`. `429` is not the same as either. Building a tool that classifies responses correctly and communicates uncertainty where it exists is the difference between automation and analysis.

---

## Learning Outcome

- Built a modular, production-shaped Python OSINT tool from scratch with argument parsing, graceful error handling, and file output.
- Practised HTTP response code interpretation as a core analyst skill `200`, `403`, `404`, and `429` each carry distinct defensive meaning.
- Translated MITRE T1589 from an offensive technique into an authorized, scoped defensive audit.
- Generated structured report output suitable for evidence documentation and README integration.
- Demonstrated that passive reconnaissance produces actionable intelligence without any network interaction with the target — reinforcing why defenders must audit their own footprint first.

---

## Repository Structure

```
soc-03-tookie-osint/
├── README.md
├── scripts/
│   └── tookie.py
├── output/
│   └── WiLL75G_footprint.txt
├── reports/
└── screenshots/
    ├── 01_folder_structure.png
    ├── 02_python_environment.png
    ├── 03_tookie_foundation.png
    ├── 06a_module1_platform_results.png
    ├── 06b_module2_dork_queries.png
    ├── 06c_module3_footprint_report.png
    ├── 07a_output_file.png
    └── 07b_output_file.png
```

---

## Conclusion

Tookie-OSINT demonstrates defensive identity reconnaissance end to end: a custom tool built from scratch, run against an authorized target, with every finding interpreted through an analyst's lens rather than accepted as raw tool output. Three confirmed profiles in seconds without a single packet reaching a protected system makes the cost of T1589 concrete. The distinction between a `404`, a `403`, and a `429` is not a technical footnote; it is the difference between a confirmed absence and an open question. Building a tool that handles that distinction correctly, and knowing how to respond to each, is what separates analyst thinking from script execution.

# Tookie-OSINT: Digital Footprint Auditor (MITRE T1589)

> Built a custom Python OSINT tool from scratch that maps a target's public digital footprint across platforms, the same identity enumeration an adversary performs before attacking, run proactively by the defender.

One username, eight platforms, three seconds: three confirmed public profiles, each leaking a different category of intelligence, and one rate-limited response the tool was careful enough not to call an absence. That last distinction, a 429 is not a 404, is the whole difference between automation and analysis.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Defensive OSINT tooling, Python |
| Tool | Tookie-OSINT, three modules, built from scratch |
| Target | WiLL75G, authorized self-audit |
| Platforms Checked | 8 |
| Profiles Confirmed | 3, GitHub, Reddit, HackerNews |
| Key Nuance | TryHackMe 429, flagged inconclusive not absent |
| Environment | Kali, Python 3, requests |
| MITRE | T1589, run as an authorized self-audit |

## What This Is

Before an attacker sends a single packet to your network, they know who works there, what platforms those people use, what they post publicly, and what their technical interests reveal about the organization's stack.

MITRE ATT&CK T1589 (Gather Victim Identity Information) describes this phase. It is passive, free, and leaves no trace on the victim's systems. If a defender has not audited their own identity exposure, the attacker already has an information advantage before anything else happens.

Tookie-OSINT was built to run that enumeration from the defender's side: a three-module Python tool that takes a username, checks for confirmed presence across eight platforms, generates targeted Google dork queries for deeper manual research, and produces a structured footprint report. It was run against the analyst's own public username `WiLL75G` as an authorized self-audit.

## Executive Summary

Identity reconnaissance is among the cheapest steps in an attacker's playbook. A username checked against eight platforms takes seconds, and the platforms themselves do the work, serving public profile pages to anyone who requests them.

Tookie-OSINT turns that into a defender's tool through three sequential modules: a platform presence checker (HTTP requests to each platform's public profile URL, with the response code interpreted, 200 is a confirmed profile, 404 a confirmed absence, 403 access-restricted rather than absent, 429 rate-limited and therefore inconclusive), a Google dork generator (ten targeted queries across platforms, document types, credential exposure, and API-key leakage), and a report generator (structured plain-text output saved to disk).

Against `WiLL75G`, the tool confirmed three public profiles with meaningful attacker value across code exposure, post history, and technical commentary, and correctly flagged a rate-limited response from TryHackMe as inconclusive rather than absent. That last behavior is the one that matters most, and it is covered below.

## Audit Target

| Attribute | Value |
| --- | --- |
| Target username | `WiLL75G` |
| Audit type | Passive OSINT, authorized self-audit |
| Platforms checked | 8 |
| Profiles confirmed | 3 |
| Tool | `tookie.py`, custom Python, built from scratch |
| Environment | Kali Linux, Python 3, `requests` library |

## Scope and Authorization

This audit was conducted against the analyst's own public username. All checks used only HTTP GET requests to publicly accessible profile URLs, the same requests any browser makes when visiting a profile page. No authentication, exploitation, brute-forcing, or scraping of protected content was performed.

Running this tool against usernames you do not own or have explicit authorization to audit is outside the scope of this project and may violate platform terms of service or applicable law.

## Investigation Methodology

### 1. Environment and Tool Setup

Verified Python 3 and the `requests` library, created the project folder structure, and confirmed the development environment on Kali Linux.

*Screenshot: `02_python_environment.png`*

### 2. Built the Tool Foundation (tookie.py skeleton)

Authored the script header, argument parser (`-u` for username, `-o` for output file), and entry point. Ran a smoke test to confirm the banner and INFO block rendered correctly before adding any OSINT logic.

*Screenshot: `03_tookie_foundation.png`*

**Analyst note**

Building a clean foundation before adding modules enforces the discipline of separating concerns, each module does one thing and returns structured data to `main()`. This makes the tool easier to extend and easier to audit, which is the same reason production code is written this way and throwaway scripts are not.

### 3. Module 1: Platform Presence Checker

Added HTTP GET checks against eight platforms using an honest User-Agent and a 6-second timeout. Each response code is interpreted and classified:

| HTTP Code | Classification | Analyst Meaning |
| --- | --- | --- |
| 200 | FOUND | Profile confirmed and publicly accessible |
| 404 | NOT FOUND | Profile does not exist on this platform |
| 403 | NOT FOUND (restricted) | Access denied, may exist but not publicly accessible |
| 429 | TIMEOUT/ERROR | Rate-limited, existence inconclusive, manual check required |

*Screenshot: `06a_module1_platform_results.png`*

**Findings:**

| Platform | Result | HTTP Code |
| --- | --- | --- |
| GitHub | FOUND | 200 |
| Reddit | FOUND | 200 |
| HackerNews | FOUND | 200 |
| TryHackMe | Inconclusive | 429 (rate-limited) |
| GitLab | Not found | 403 |
| Medium | Not found | 403 |
| Keybase | Not found | 404 |
| Dev.to | Not found | 404 |

### 4. Module 2: Google Dork Generator

Added generation of ten targeted dork queries covering platform presence, document exposure, paste sites, credential mentions, and API-key leakage, all tied to the target username.

*Screenshot: `06b_module2_dork_queries.png`*

**Analyst note**

The dork generator is deliberately passive, it produces queries for manual execution rather than automating searches, giving the analyst full control over what gets queried and when. Dorks [08]–[10] (`intext:"password"`, `"API key"`, `"access token"`) are the highest-value from a defensive standpoint: if they return results, there is a credential or secret exposure that requires immediate action.

### 5. Module 3: Report Generator

Added a structured report consolidating platform results, confirmed profile URLs, dork queries, and analyst notes into a plain-text file written to `output/`. The `-o` flag triggers the file write; without it the report prints to terminal only.

*Screenshots: `06c_module3_footprint_report.png`, `07a_output_file.png`, `07b_output_file.png`*

## Digital Footprint Findings (Exposed Indicators)

| Platform | Confirmed URL | Attacker Intelligence Value |
| --- | --- | --- |
| GitHub | `https://github.com/WiLL75G` | Repository names, commit history, programming languages, potential email address in commits |
| Reddit | `https://www.reddit.com/user/WiLL75G` | Post and comment history, subreddit memberships, interests, account age |
| HackerNews | `https://news.ycombinator.com/user?id=WiLL75G` | Technical commentary, interests, professional context |

**TryHackMe (429 inconclusive):** The platform returned a rate-limit response rather than a 404. The profile may exist. Manual verification required.

**Generated dork queries:** 10 queries across platform presence, document exposure (`filetype:pdf`, `filetype:doc`), paste sites, credential mentions, and API-key searches.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
| --- | --- | --- | --- |
| Reconnaissance | Gather Victim Identity Information | T1589 | Passive enumeration of a target username's public presence across platforms, the identity mapping an adversary performs before any direct network interaction. Run here defensively, as an authorized self-audit. |

## Findings

- Three public profiles confirmed: GitHub, Reddit, HackerNews, each exposing a distinct intelligence category (code, social, technical commentary).
- GitHub exposes the most operationally sensitive data: repository names reveal technologies in use, commit history may expose email addresses, and public repos may contain secrets committed accidentally.
- TryHackMe returned 429 (rate-limited), not 404. The profile may exist. The tool correctly classified this as inconclusive rather than absent. Manual verification recommended.
- No credential or API-key exposure detected in this run, dork queries [08]–[10] should be run manually to confirm.
- Username `WiLL75G` is consistent across confirmed platforms, so an attacker correlating identity across platforms has a high-confidence match.

## Response

For an organization auditing employee or service-account usernames:

1. Review GitHub email visibility settings, commit history can expose email addresses even when the profile hides them.
2. Audit Reddit and HackerNews post history for sensitive organizational information, technology disclosures, or security questions.
3. Manually verify any 429 responses, rate-limited platforms require a browser check to confirm presence or absence.
4. Run the credential dork queries (`intext:"password"`, `"API key"`, `"access token"`) manually and investigate any results immediately.
5. Run Tookie-OSINT on a recurring schedule against critical usernames, exposure changes as users create accounts, post content, or commit code.

## The SOC Angle

The most instructive moment in this audit was the TryHackMe 429.

A less careful tool, or a less careful analyst, classifies that as "not found" and moves on. But it is not not-found. It is rate-limited, which means the platform detected automated querying and refused to answer, so the profile may well exist. That single distinction is the difference between a closed gap and an open one that was merely mislabeled closed.

It is also the reminder that tool output requires interpretation. HTTP response codes are not binary. 403 is not 404, and 429 is neither. A tool that flattens all three into "absent" is confidently wrong a third of the time. Building one that classifies responses correctly and communicates uncertainty where it exists is the line between automation and analysis, and it is the same instinct that separates a Tier 1 analyst who closes tickets from one who closes them correctly.

## What This Demonstrates

Building a modular, production-shaped Python OSINT tool from scratch with argument parsing, graceful error handling, and file output.

Interpreting HTTP response codes as a core analyst skill, 200, 403, 404, and 429 each carry distinct defensive meaning.

Translating MITRE T1589 from an offensive technique into an authorized, scoped defensive audit.

Producing structured report output suitable for evidence documentation and README integration.

Demonstrating that passive reconnaissance yields actionable intelligence without any network interaction with the target, which is exactly why defenders must audit their own footprint first.

Communicating uncertainty honestly, flagging an inconclusive result rather than forcing it into a clean yes or no.

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

## Conclusion

Tookie-OSINT demonstrates defensive identity reconnaissance end to end: a custom tool built from scratch, run against an authorized target, with every finding interpreted through an analyst's lens rather than accepted as raw tool output. Three confirmed profiles in seconds, without a single packet reaching a protected system, makes the cost of T1589 concrete. The distinction between a 404, a 403, and a 429 is not a technical footnote, it is the difference between a confirmed absence and an open question. Building a tool that handles that distinction correctly, and knowing how to respond to each, is what separates analyst thinking from script execution.

---

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=flat&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

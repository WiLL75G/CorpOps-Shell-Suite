# SMTP-Analyzer: Phishing Header Analysis (MITRE T1566)

> Built a custom Python tool that parses raw email headers, extracts forensic fields, checks SPF/DKIM/DMARC authentication, scores phishing indicators, and produces a structured verdict, the complete Tier 1 analyst workflow for a suspicious email landing in the SOC queue.

A phishing score of 130 out of 130, the maximum possible, built from seven weighted indicators that every one fired. SPF failed, DKIM absent, DMARC failed, replies routed to a Russian host, Return-Path mismatched, a bulk PHP mailer fingerprint, and the receiving server's own spam filter already flagging it. Seven independent signals, one direction.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Email header forensics, Python |
| Tool | SMTP-Analyzer, five modules, built from scratch |
| Sample | phishing_sample.eml, PayPal impersonation |
| Apparent Sender | security@paypal.com |
| Actual Infrastructure | suspicious-mailer.ru, 185.220.101.45 |
| Phishing Score | 130 / 130, seven indicators |
| Verdict | HIGH RISK, likely phishing |
| MITRE | T1566 |

## What This Is

The capstone of the CorpOps Shell Suite, and the point where detection reaches the email layer, where most attacks actually start.

When a user forwards a suspicious email to the SOC, the first analyst action is pulling the raw headers. Headers tell the real story: where the email actually came from, what servers it passed through, whether authentication passed or failed, and whether the visible sender matches the actual sending infrastructure. SMTP-Analyzer automates that triage into a single structured report.

Project 06 (Whois-Guard) caught phishing infrastructure at domain registration. Project 08 catches the phishing email itself, after it lands in a mailbox, at the moment of SOC triage. Together they bracket the phishing lifecycle from the attacker's first public artifact to the message in the inbox.

## Incident Summary

A suspicious email was forwarded to the Nexus Corp SOC by an employee. It appeared to be from PayPal Security (`security@paypal.com`) warning that the recipient's account had been limited. The raw headers were extracted and analyzed using SMTP-Analyzer, a custom Python tool built for structured phishing triage.

The analysis returned a phishing score of 130 out of 130, the maximum possible. Every detection module fired: SPF failed, DKIM was absent, DMARC failed, the Reply-To domain pointed to a Russian hosting provider, the Return-Path revealed a different sending infrastructure, the X-Mailer identified a bulk PHP mailer, and the receiving server's own spam filter had already flagged the message. Seven independent indicators, all pointing the same direction.

A 130/130 is not a close call, and that is worth stating plainly: the value of the tool is not catching this email, any filter would, it is producing a defensible, itemized record of *why* it is phishing that survives being pasted into an incident ticket.

**Verdict: HIGH RISK, confirmed phishing.**

## Executive Summary

MITRE ATT&CK T1566 (Phishing) is the final project in the CorpOps Shell Suite and closes the detection loop. When a user forwards a suspicious email to the SOC, the headers are where the real story lives, and SMTP-Analyzer automates reading them into a single structured report.

The tool runs five sequential modules: an email header parser (loads the `.eml` via Python's built-in `email` library into a structured object), forensic field extraction (the fields a SOC analyst checks first: `From`, `Reply-To`, `Return-Path`, `Received` chain, `X-Mailer`, and spam flags), an SPF/DKIM/DMARC authentication check (reads `Authentication-Results` for the three verdicts that exist specifically to detect spoofing), a phishing indicator scorer (weighted points per red flag producing a LOW/MODERATE/HIGH verdict), and a phishing analysis report (structured output suitable for a phishing incident ticket, threat-intel submission, or Tier 2 escalation).

## Affected System (Analyzed Email)

| Attribute | Value |
| --- | --- |
| File analyzed | `phishing_sample.eml` |
| Apparent sender | `"PayPal Security" <security@paypal.com>` |
| Actual sending infrastructure | `suspicious-mailer.ru` (`185.220.101.45`) |
| Target recipient | `james@nexuscorp.com` |
| Message-ID | `<20260630091523.x1234abc@suspicious-mailer.ru>` |
| Phishing score | 130 / 130 |
| Verdict | HIGH RISK, likely phishing |
| Report generated | 2026-07-05 07:10:05 |
| Tool | `smtp-analyzer.py`, custom Python, built from scratch |
| Environment | Kali Linux, Python 3.13, standard library only |

## Scope and Authorization

This analysis was conducted against a synthetic `.eml` file crafted in the lab to simulate a realistic phishing email. No real email accounts, real users, or external mail servers were involved. The sample was designed to demonstrate every major phishing indicator class simultaneously. SMTP-Analyzer performs read-only parsing of locally stored email files, no network requests are made during analysis.

## Investigation Methodology

### 1. Sample Email Creation

Crafted a realistic phishing `.eml` file simulating a PayPal impersonation attack. The sample was designed with seven deliberate red flags covering authentication failure, domain spoofing, reply-to misdirection, bulk-mailer fingerprinting, and spam scoring.

*Screenshot: `02_phishing_sample.png`*

**Red flags built into the sample:**

| Field | Crafted Value | Red Flag |
| --- | --- | --- |
| From | `"PayPal Security" <security@paypal.com>` | Display name and address designed to appear legitimate |
| Reply-To | `collect@suspicious-mailer.ru` | Replies harvested by attacker, not PayPal |
| Return-Path | `bounce@suspicious-mailer.ru` | Reveals real sending infrastructure |
| SPF | `fail` | Sending IP not authorized for `paypal.com` |
| DKIM | `none` | No cryptographic signature present |
| DMARC | `fail` | Authentication policy violated |
| X-Mailer | `PHPMailer 5.2.0` | Bulk PHP mailer, not enterprise platform |
| Subject | Base64 encoded "URGENT: Your PayPal Account Has Been Limited" | Social engineering urgency trigger |
| Sending IP | `185.220.101.45` | Russian hosting provider |

### 2. Module 1: Email Header Parser

Loaded the `.eml` file using Python's built-in `email` library, which handles MIME encoding, multi-line headers, and encoded subjects automatically.

**SOC Observation**

The subject line arrived Base64-encoded as `=?UTF-8?B?VVJHRU5UOiBZb3VyIFBheVBhbCBBY2NvdW50IEhhcyBCZWVuIExpbWl0ZWQ=?=`. Decoded: "URGENT: Your PayPal Account Has Been Limited." The word URGENT is a social-engineering pressure tactic designed to make the recipient act without thinking, and the encoding itself is a small tell, a legitimate sender has no reason to obscure its own subject line, but MIME encoding can also slip a payload past a filter matching on plaintext keywords.

### 3. Module 2: Forensic Field Extraction

*Screenshot: `03a_forensic_fields.png`*

The forensic fields were extracted from the sample. The decisive one is the mismatch: the visible `From` claims `paypal.com`, while both `Reply-To` (`collect@suspicious-mailer.ru`) and `Return-Path` (`bounce@suspicious-mailer.ru`) resolve to `suspicious-mailer.ru`. A legitimate sender's reply and bounce paths stay within its own domain; a divergence this clean is spoofing made visible. The `X-Spam-Flag: YES` and `X-Mailer: PHPMailer 5.2.0` fields round out the picture, the receiving server already suspected the message, and the mailer is a bulk PHP tool no enterprise sender uses.

**Received chain analysis (2 hops):**

```
Hop 1: from suspicious-mailer.ru (suspicious-mailer.ru [185.220.101.45])
    by mail.nexuscorp.com
Hop 2: from localhost (localhost [127.0.0.1])
    by suspicious-mailer.ru with ESMTP id x1234abc
```

The chain is the one part of a header an attacker cannot fully forge, because each relay stamps the hop it received. Reading bottom to top, the message originates at `localhost` on `suspicious-mailer.ru` and is handed to `mail.nexuscorp.com` directly from `185.220.101.45`. At no point does any PayPal infrastructure appear. The visible `From` says PayPal; the transport path says a single Russian host talking straight to the victim's mail server.

### 4. Module 3: SPF/DKIM/DMARC Authentication Check

*Screenshot: `03b_authentication.png`*

The module read the `Authentication-Results` header and extracted the three verdicts:

| Mechanism | Result | Meaning |
| --- | --- | --- |
| SPF | `fail` | The sending IP is not authorized to send for the claimed domain |
| DKIM | `none` | No cryptographic signature is present to verify the sender |
| DMARC | `fail` | The message violates the domain's published authentication policy |

SPF, DKIM, and DMARC exist for exactly one purpose: to answer "is this sender who it claims to be." Here all three independently say no. Any one failing might be a misconfiguration on a legitimate sender; all three failing together, on a message that also mismatches its reply paths, is not a configuration problem, it is a forgery.

### 5. Module 4: Phishing Indicator Scorer

*Screenshot: `03c_score_and_verdict.png`*

The scorer assigns weighted points per indicator and sums them to a verdict. Against this sample, all seven fired for the maximum 130:

| Points | Indicator | What it proves |
| --- | --- | --- |
| +25 | SPF fail | Sending IP not authorized for the claimed domain |
| +25 | DMARC fail | Email authentication policy violated |
| +20 | DKIM fail/none | No cryptographic email signature |
| +20 | Reply-To domain mismatch | From paypal.com vs Reply-To suspicious-mailer.ru |
| +15 | Return-Path domain mismatch | From paypal.com vs Return-Path suspicious-mailer.ru |
| +15 | X-Spam-Flag: YES | Receiving spam filter already flagged the message |
| +10 | Suspicious X-Mailer | PHPMailer 5.2.0, a bulk PHP mailer |
| **130** | **Total** | **HIGH RISK, likely phishing** |

The weighting is the point of this module, and it is deliberate rather than arbitrary. The authentication failures (SPF, DKIM, DMARC) carry the heaviest weight because they are the hardest signals to fake, followed by the infrastructure mismatches, with the mailer fingerprint weighted lightest because on its own it is only suggestive. The score is not a headline number, it is a defensible sum an analyst can walk a reviewer through line by line.

### 6. Module 5: Phishing Analysis Report

The four modules are consolidated into a single structured report written to `output/`, timestamped and suitable for attaching to a phishing incident ticket, submitting to a threat-intel platform, or escalating to Tier 2. The report reproduces the forensic fields, the Received chain, the authentication results, the scored indicators, and analyst notes in one artifact.

## Indicators of Compromise (IOCs)

| Type | Indicator |
| --- | --- |
| Sending IP | `185.220.101.45` |
| Attacker infrastructure | `suspicious-mailer.ru` |
| Reply-To | `collect@suspicious-mailer.ru` |
| Return-Path | `bounce@suspicious-mailer.ru` |
| Message-ID | `<20260630091523.x1234abc@suspicious-mailer.ru>` |
| X-Mailer | `PHPMailer 5.2.0` |
| Spoofed brand | PayPal (`security@paypal.com`) |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
| --- | --- | --- | --- |
| Initial Access | Phishing | T1566 | Analysis of a delivered phishing email at the header layer, authentication verdicts, sender-infrastructure mismatch, and bulk-mailer fingerprinting used to confirm a spoofed message at the point of SOC triage. |

## Findings

- All three email authentication mechanisms failed or were absent: SPF fail, DKIM none, DMARC fail.
- The visible From domain (`paypal.com`) matches neither the Reply-To nor the Return-Path, both of which resolve to `suspicious-mailer.ru`.
- The Received chain shows the message originating from a single host, `185.220.101.45` / `suspicious-mailer.ru`, with no PayPal infrastructure anywhere in the transport path.
- The X-Mailer identifies PHPMailer 5.2.0, a bulk PHP mailer inconsistent with a genuine enterprise sender.
- The receiving server's own spam filter had already set `X-Spam-Flag: YES`.
- Seven indicators fired for a maximum score of 130/130, verdict HIGH RISK.

## Response

Defender actions for a confirmed phishing message of this profile:

1. Block the sender domain `suspicious-mailer.ru` and IP `185.220.101.45` at the email gateway.
2. Quarantine any similar messages already delivered, and sweep other mailboxes for the same campaign (shared Message-ID pattern, sending IP, or subject).
3. Alert the targeted user, `james@nexuscorp.com`, and confirm no reply was sent to the harvesting Reply-To address.
4. Submit the IOCs to threat-intel platforms (PhishTank, APWG) so the infrastructure is flagged for other defenders.
5. Preserve the raw `.eml` and the analysis report as the incident evidence artifact.

## The SOC Angle

The point of this tool is not catching a 130/130 email, any spam filter catches that one. The point is the itemized, defensible record it produces.

When Tier 2 or an incident report asks "how do you know this is phishing," the answer cannot be "the filter said so." It has to be seven named indicators, each tied to a specific header field, each independently verifiable, and each carrying a weight you can justify. SMTP-Analyzer produces exactly that: a verdict an analyst can stand behind line by line. The skill this demonstrates is not spotting an obvious phish, it is reading a header well enough to prove one.

The seven-indicator convergence is the deeper lesson. Any single failed check could be a misconfiguration, SPF alone fails on legitimate mail all the time. It is the convergence, authentication failure and infrastructure mismatch and a spam flag and a bulk-mailer fingerprint all agreeing, that turns suspicion into a verdict. The scorer encodes that judgment by weighting the hard-to-fake signals heaviest. A good analyst weighs the stack, not the single flag, and this tool is that instinct written down.

## What This Demonstrates

Building a five-module Python email-forensics tool from scratch using only the standard library.

Reading the forensic header fields a Tier 1 analyst checks first, and knowing what each proves.

Reconstructing a Received chain to trace true message origin past a forged From address.

Interpreting SPF, DKIM, and DMARC verdicts as spoofing signals rather than opaque status strings.

Decoding a Base64 subject line and recognizing the social-engineering trigger inside it.

Designing a weighted scorer whose 130-point total is defensible line by line rather than arbitrary.

Producing a structured phishing verdict and IOC set suitable for an incident ticket or Tier 2 escalation.

## Repository Structure

```
Project-08-SMTP-Phishing-Analysis/
├── README.md
├── scripts/
│   └── smtp-analyzer.py
├── samples/
│   └── phishing_sample.eml
├── output/
│   └── phishing_report.txt
└── screenshots/
    ├── 01_folder_structure.png
    ├── 02_phishing_sample.png
    ├── 03a_forensic_fields.png
    ├── 03b_authentication.png
    └── 03c_score_and_verdict.png
```

## Conclusion

SMTP-Analyzer completes the CorpOps Shell Suite by bringing detection to the email layer, the point where most attacks actually start. A phishing email that scores 130/130 is not a subtle threat: it fails every authentication check, routes replies to attacker infrastructure, shows a single Russian host in its transport path, uses a bulk mailer fingerprint, and gets caught by the receiving server's own spam filter. The analyst's job is to read all seven signals, understand what each one proves, and produce a verdict that is defensible in an incident report. That is what this tool is built to support, and that is the loop the full suite has been building toward: from the first Nmap probe in Project 01 to the phishing email landing in the inbox in Project 08, reconnaissance, OSINT, enrichment, domain spoofing, and now the attack itself, all seen from the defender's side.

---

[![GitHub](https://img.shields.io/badge/GitHub-WiLL75G-181717?style=flat&logo=github&logoColor=white)](https://github.com/WiLL75G)
[![X](https://img.shields.io/badge/X-%40WilliamInCyber-000000?style=flat&logo=x&logoColor=white)](https://x.com/WilliamInCyber)

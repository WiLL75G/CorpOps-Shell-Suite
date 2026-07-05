# Project 08  SMTP-Analyzer: Phishing Header Analysis (MITRE T1566)

> Built a custom Python tool that parses raw email headers, extracts forensic fields, checks SPF/DKIM/DMARC authentication, scores phishing indicators, and produces a structured verdict  the complete Tier 1 analyst workflow for a suspicious email landing in the SOC queue.

---

## Incident Summary

A suspicious email was forwarded to the Nexus Corp SOC by an employee. The email appeared to be from PayPal Security (`security@paypal.com`) warning that the recipient's account had been limited. The raw headers were extracted and analyzed using **SMTP-Analyzer**, a custom Python tool built for structured phishing triage.

The analysis returned a **phishing score of 130 out of 130**  the maximum possible. Every detection module fired. SPF failed, DKIM was absent, DMARC failed, the Reply-To domain pointed to a Russian hosting provider, the Return-Path revealed a different sending infrastructure, the X-Mailer identified a bulk PHP mailer, and the receiving server's own spam filter had already flagged the message. Seven independent indicators, all pointing the same direction.

**Verdict: HIGH RISK  confirmed phishing.**

---

## Executive Summary

**MITRE ATT&CK T1566 (Phishing)** is the final project in the CorpOps Shell Suite and closes the detection loop. Project 06 (Whois-Guard) caught phishing infrastructure at domain registration. Project 08 catches the phishing email itself  after it lands in a mailbox, at the moment of SOC triage.

When a user forwards a suspicious email to the SOC, the first analyst action is pulling the raw headers. Headers tell the real story: where the email actually came from, what servers it passed through, whether authentication passed or failed, and whether the visible sender matches the actual sending infrastructure. SMTP-Analyzer automates that triage into a single structured report.

The tool runs five sequential modules:

1. **Email Header Parser**  loads the `.eml` file using Python's built-in `email` library and converts it into a structured object all subsequent modules can query.
2. **Forensic Field Extraction**  pulls the six fields a SOC analyst checks first: `From`, `Reply-To`, `Return-Path`, `Received` chain, `X-Mailer`, and spam flags.
3. **SPF/DKIM/DMARC Authentication Check**  reads the `Authentication-Results` header and extracts the three authentication verdicts that exist specifically to detect email spoofing.
4. **Phishing Indicator Scorer**  assigns weighted points for each red flag and produces a LOW/MODERATE/HIGH verdict from the total.
5. **Phishing Analysis Report**  structured output suitable for a phishing incident ticket, threat intelligence submission, or escalation to Tier 2.

---

## Affected System (Analyzed Email)

| Attribute | Value |
|---|---|
| File analyzed | `phishing_sample.eml` |
| Apparent sender | `"PayPal Security" <security@paypal.com>` |
| Actual sending infrastructure | `suspicious-mailer.ru` (`185.220.101.45`) |
| Target recipient | `james@nexuscorp.com` |
| Phishing score | 130 / 130 |
| Verdict | HIGH RISK  likely phishing |
| Tool | `smtp-analyzer.py`  custom Python, built from scratch |
| Environment | Kali Linux, Python 3.13, standard library only |

---

## Scope and Authorization

This analysis was conducted against a synthetic `.eml` file crafted in the lab to simulate a realistic phishing email. No real email accounts, real users, or external mail servers were involved. The sample was designed to demonstrate every major phishing indicator class simultaneously. SMTP-Analyzer performs read-only parsing of locally stored email files  no network requests are made during analysis.

---

## Investigation Methodology

### 1. Sample Email Creation
Crafted a realistic phishing `.eml` file simulating a PayPal impersonation attack. The sample was designed with seven deliberate red flags covering authentication failure, domain spoofing, reply-to misdirection, bulk-mailer fingerprinting, and spam scoring.

*Screenshot: `02_phishing_sample.png`*

**Red flags built into the sample:**

| Field | Crafted Value | Red Flag |
|---|---|---|
| From | `"PayPal Security" <security@paypal.com>` | Display name and address designed to appear legitimate |
| Reply-To | `collect@suspicious-mailer.ru` | Replies harvested by attacker, not PayPal |
| Return-Path | `bounce@suspicious-mailer.ru` | Reveals real sending infrastructure |
| SPF | `fail` | Sending IP not authorized for `paypal.com` |
| DKIM | `none` | No cryptographic signature present |
| DMARC | `fail action=quarantine` | Authentication policy violated |
| X-Mailer | `PHPMailer 5.2.0` | Bulk PHP mailer, not enterprise platform |
| Subject | Base64 encoded "URGENT: Your PayPal Account Has Been Limited" | Social engineering urgency trigger |
| Sending IP | `185.220.101.45` | Russian hosting provider |

### 2. Module 1  Email Header Parser
Loaded the `.eml` file using Python's built-in `email` library. The library handles MIME encoding, multi-line headers, and encoded subjects automatically.

**SOC Observation:** The subject line was Base64 encoded. Decoded value: "URGENT: Your PayPal Account Has Been Limited." The word URGENT is a social engineering pressure tactic designed to make the recipient act without thinking.

### 3. Module 2  Forensic Field Extraction

*Screenshot: `03a_forensic_fields.png`*

**Received chain analysis:**



---

## Conclusion

SMTP-Analyzer completes the CorpOps Shell Suite by bringing detection to the email layer  the point where most attacks actually start. A phishing email that scores 130/130 is not a subtle threat: it fails every authentication check, routes replies to attacker infrastructure, uses a bulk mailer fingerprint, and gets caught by the receiving server's own spam filter. The analyst's job is to read all seven signals, understand what each one proves, and produce a verdict that is defensible in an incident report. That is what this tool is built to support, and that is the loop the full suite has been building toward: from the first Nmap probe in Project 01 to the phishing email landing in the inbox in Project 08  reconnaissance, OSINT, enrichment, domain spoofing, and now the attack itself, all seen from the defender's side.

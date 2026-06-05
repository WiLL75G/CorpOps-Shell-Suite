# WebSift Public Web Footprint Auditor (MITRE T1593)

> A custom-built defensive OSINT tool that audits the public web footprint of a target the same reconnaissance an attacker performs first, run proactively by the blue team. Built from scratch in Python as part of the CorpOps Shell Suite.

---

## Audit Summary

A defensive reconnaissance audit was conducted to answer a single question a CISO cares about: **"What can an attacker learn about us from public sources, without ever touching our network?"** To answer it, a purpose-built tool **WebSift** was developed from scratch and used to enumerate the public footprint of a web target: disclosed technology, exposed crawl directives, and missing security controls. All activity was passive and limited to information the target already serves publicly. Findings were analyzed from a defender's perspective and translated into hardening recommendations.

## Executive Summary

Reconnaissance is the first phase of nearly every intrusion, and **MITRE ATT&CK T1593 (Search Open Websites/Domains)** is among the cheapest steps an adversary can take no packets to the victim's network, just queries against public sources. If an organization has not audited its own footprint, the attacker has effectively won the reconnaissance round before any alert could fire.

To operationalize this defensively, WebSift was built as a four-module Python tool that, given a target URL, performs:

1. **HTTP technology fingerprinting** identifies disclosed server/stack details and flags version numbers (which map directly to known CVEs).
2. **robots.txt / sitemap.xml parsing** surfaces paths and structure the site publishes to crawlers, which often act as a map to sensitive locations.
3. **Security-header auditing** checks for the presence of six recommended protective headers and reports gaps as an actionable hardening checklist.

The tool was first validated against a hardened control target (`example.com`), which disclosed minimal information, then run against an authorized real-world target (`scanme.nmap.org`). The contrast was instructive: the control disclosed almost nothing, while the real target leaked its exact web server version (**Apache/2.4.7 (Ubuntu)**) and was missing **all six** recommended security headers. Both results were produced in seconds demonstrating how quickly an attacker maps an under-hardened footprint, and why defenders must do it first.

## Affected System (Audited Targets)

| Role | Target | Purpose |
|---|---|---|
| Control (hardened baseline) | `https://example.com` | IANA-reserved domain used to establish what a minimal-disclosure footprint looks like |
| Authorized live target | `http://scanme.nmap.org` | A host explicitly sanctioned by its operator for scanning and testing |

**Tooling environment:** Kali Linux (analyst workstation), Python 3.13, `requests` 2.32. WebSift authored from scratch; no third-party scanning tools used.

## Scope & Authorization

This audit was conducted strictly against targets that are either purpose-built for testing (`example.com`, IANA-reserved for documentation) or explicitly authorized for scanning by their operator (`scanme.nmap.org`). WebSift performs only passive, read only requests for resources the target already serves publicly. It performs no authentication, no exploitation, no brute-forcing, and no active vulnerability probing. Public availability of data does not imply authorization to test arbitrary systems; documenting scope is a deliberate part of the methodology.

## Investigation Methodology

### 1. Built the HTTP fetch core (Module 1)
Authored a Python class that fetches a target once and stores the response for all subsequent analysis efficient and minimizing requests to the target. The fetch routine uses an honest User-Agent, a request timeout, and graceful handling of timeout/connection/other failure modes so the tool reports problems cleanly rather than crashing.

*Evidence: `websift_module1_fetch_test.png`*

**Analyst note:** Building the fetch core as a reusable foundation (one request, many analyses) is both an engineering decision and an ethical one — it avoids hammering the target with redundant requests.

### 2. Implemented technology fingerprinting (Module 2)
Added analysis of response headers that commonly disclose technology and version information (`Server`, `X-Powered-By`, and similar). The module flags any value containing a version number, since exact versions map directly to known CVEs.

*Evidence: `websift_module2_header_fingerprint.png`*

**Finding (control target):** `example.com` disclosed only `Server: cloudflare` a generic CDN identifier with no version. This established the "good footprint" baseline.

### 3. Implemented robots.txt & sitemap.xml parsing (Module 3)
Added targeted retrieval and parsing of the two files sites publish for crawlers. `Disallow:` entries are highlighted because administrators frequently list sensitive paths there to hide them from search engines but the file is public, so it can become a map for an attacker.

*Evidence: `websift_module3_robots_sitemap.png`*

**Analyst note:** The module is designed to treat absence as a clean, reported result rather than an error, demonstrating defensive handling of the common "file not present" case.

### 4. Implemented security-header auditing (Module 4)
Added a check for six recommended security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), producing a present/missing score and an actionable hardening checklist the most directly defensive output of the tool.

*Evidence: `websift_full_audit_scanme_2.png`*

### 5. Validated against a control, then ran the live audit
Ran the complete four-module tool against the hardened control (`example.com`) and then the authorized live target (`scanme.nmap.org`), comparing the disclosure profiles.

*Evidence: `websift_full_audit_scanme_1.png`, `websift_full_audit_scanme_2.png`*

**Finding (live target):** `scanme.nmap.org` disclosed `Server: Apache/2.4.7 (Ubuntu)` (exact version) and scored **0/6** on security headers.

## Findings & Indicators

| Category | Control (`example.com`) | Live target (`scanme.nmap.org`) | Defender significance |
|---|---|---|---|
| Server disclosure | `cloudflare` (generic) | `Apache/2.4.7 (Ubuntu)` | Exact version → direct CVE lookup |
| Version leaked? | No | **Yes** | Removes attacker guesswork |
| robots.txt | None | None | No path disclosure in either case |
| sitemap.xml | None | None | No structure disclosure |
| Security headers | Behind hardened CDN | **0 / 6 present** | No browser-side defenses |

**Key disclosed indicators (live target):**
- Web server software and version: `Apache/2.4.7 (Ubuntu)`
- Missing controls: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application in this Audit |
|---|---|---|---|
| Reconnaissance | Search Open Websites/Domains | T1593 | Public, passive collection of a target's disclosed technology, crawl directives, and security posture — the information an adversary gathers before any direct interaction with the victim network. |

## Analyst Findings

- The live target discloses its **exact web server version**, removing an attacker's need to guess and enabling direct mapping to known CVEs for that build.
- The live target presents **no recommended security headers**, indicating minimal browser-side hardening and a weaker posture against downgrade, clickjacking, MIME-sniffing, and cross-site scripting classes of attack.
- Neither target exposed `robots.txt` or `sitemap.xml`, so no crawl-path or structural disclosure occurred.
- The hardened control target demonstrates that minimal disclosure is achievable: a generic CDN-fronted footprint reveals neither version nor origin details.

## Response & Recommendations

For a real organization presenting the live target's profile, the defensive actions would be:

1. **Suppress version disclosure** configure the web server (or fronting CDN) to emit a generic `Server` header without a version string, so reconnaissance cannot map exact CVEs.
2. **Add the six recommended security headers** at the server or CDN layer, prioritizing HSTS (forces HTTPS), CSP (mitigates XSS), and X-Frame-Options (mitigates clickjacking).
3. **Front the origin with a CDN/proxy** where feasible, as the control target does, to shield origin software and version details.
4. **Adopt proactive footprint auditing** as a recurring control, so disclosure regressions are caught by the defender before an adversary finds them.

## Analyst Insight

The most valuable outcome of this project was not any single finding but the demonstration that footprint disclosure is a spectrum, and that the difference between a hardened and an under-hardened posture is visible in seconds to anyone attacker or defender. Building the tool from scratch reinforced a core lesson: defensive reconnaissance is not about exotic capability, it is about systematically looking at what you already expose. The contrast between a CDN-fronted control that disclosed almost nothing and a legacy host that volunteered its exact Apache version made the abstract risk of T1593 concrete. A defender who runs this audit first turns an attacker's cheapest advantage into a closed gap.

## Learning Outcome

- Designed and built a multi-module security tool from scratch in Python, with reusable architecture, CLI arguments, and graceful error handling.
- Translated an offensive reconnaissance technique (T1593) into a defensive, authorized, scoped audit.
- Interpreted HTTP technology and security headers from a defender's perspective, connecting disclosure to concrete attacker advantage (CVE mapping) and concrete hardening actions.
- Used a hardened control target to establish a baseline, then measured a real target against it a comparative methodology that strengthens any finding.
- Practiced disciplined scope and authorization documentation appropriate to OSINT and reconnaissance work.

## Repository Structure

```
soc-02-websift-web-asset-audit/
├── README.md
├── tools/
│   └── websift.py            # the custom four-module auditor
├── output/                   # saved scan output (optional)
├── reports/                  # written report / PDF
└── screenshots/
    ├── websift_environment_check.png
    ├── websift_requests_check.png
    ├── websift_project_structure.png
    ├── websift_module1_fetch_test.png
    ├── websift_module2_header_fingerprint.png
    ├── websift_module3_robots_sitemap.png
    ├── websift_full_audit_scanme_1.png
    └── websift_full_audit_scanme_2.png
```

## Conclusion

WebSift demonstrates defensive reconnaissance end to end: a custom tool, built from scratch, used to audit a target's public footprint exactly as an attacker would but proactively, with scope and authorization, and with findings turned into hardening actions. The comparative result (a minimal-disclosure control versus a version-leaking, header-less live target) makes the value of MITRE T1593 awareness tangible: the cheapest step in an attacker's playbook is also the easiest for a defender to take first. Auditing your own footprint before someone else does is among the highest-leverage moves a blue team can make.

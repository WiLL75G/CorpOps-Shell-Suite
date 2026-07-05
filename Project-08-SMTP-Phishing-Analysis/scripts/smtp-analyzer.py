#!/usr/bin/env python3
###############################################################################
# smtp-analyzer.py
#
# Purpose:  SMTP phishing header analyzer  parses raw email headers,
#           extracts forensic fields, checks SPF/DKIM/DMARC authentication,
#           scores phishing indicators, and produces a structured verdict.
# Author:   James Williams (WiLL75G)
# Project:  CorpOps Shell Suite / Project 08 - SMTP Analyzer
# MITRE:    T1566 - Phishing
#
# Usage:    python3 smtp-analyzer.py -f <email.eml>
# Example:  python3 smtp-analyzer.py -f samples/phishing_sample.eml
###############################################################################

import argparse
import email
import re
from datetime import datetime

BANNER = """
=============================================================
  SMTP-ANALYZER -- CorpOps SOC Tier 1
  Phishing Header Analysis Tool
  MITRE ATT&CK: T1566 (Phishing)
=============================================================
"""

SUSPICIOUS_MAILERS = [
    "phpmailer", "sendblaster", "mailchimp", "massmailer",
    "bulk", "blaster", "sender", "smtp2go", "sendinblue"
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="SMTP-Analyzer: Phishing header analysis tool"
    )
    parser.add_argument("-f", "--file", required=True,
                        help="Path to .eml file to analyze")
    parser.add_argument("-o", "--output", default=None,
                        help="Save report to file (optional)")
    return parser.parse_args()


def load_email(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        return email.message_from_file(f)


def extract_forensic_fields(msg):
    print("-------------------------------------------------------------")
    print("  MODULE 2 -- Forensic Field Extraction")
    print("-------------------------------------------------------------")

    fields = {}

    fields['from']        = msg.get('From', 'Not present')
    fields['reply_to']    = msg.get('Reply-To', 'Not present')
    fields['return_path'] = msg.get('Return-Path', 'Not present')
    fields['to']          = msg.get('To', 'Not present')
    fields['subject']     = msg.get('Subject', 'Not present')
    fields['date']        = msg.get('Date', 'Not present')
    fields['message_id']  = msg.get('Message-ID', 'Not present')
    fields['x_mailer']    = msg.get('X-Mailer', 'Not present')
    fields['x_spam_flag'] = msg.get('X-Spam-Flag', 'Not present')
    fields['x_spam_score']= msg.get('X-Spam-Status', 'Not present')

    received = msg.get_all('Received', [])
    fields['received_chain'] = received

    print(f"  [INFO] From          : {fields['from']}")
    print(f"  [INFO] Reply-To      : {fields['reply_to']}")
    print(f"  [INFO] Return-Path   : {fields['return_path']}")
    print(f"  [INFO] To            : {fields['to']}")
    print(f"  [INFO] Subject       : {fields['subject']}")
    print(f"  [INFO] Date          : {fields['date']}")
    print(f"  [INFO] Message-ID    : {fields['message_id']}")
    print(f"  [INFO] X-Mailer      : {fields['x_mailer']}")
    print(f"  [INFO] X-Spam-Flag   : {fields['x_spam_flag']}")
    print(f"  [INFO] X-Spam-Status : {fields['x_spam_score']}")
    print("")
    print(f"  [INFO] Received chain ({len(received)} hops):")
    for i, hop in enumerate(received, 1):
        print(f"    Hop {i}: {hop.strip()[:80]}")
    print("")

    return fields


def check_authentication(msg):
    print("-------------------------------------------------------------")
    print("  MODULE 3 -- SPF / DKIM / DMARC Authentication")
    print("-------------------------------------------------------------")

    auth_results = msg.get('Authentication-Results', '')
    auth = {
        'spf'  : 'not found',
        'dkim' : 'not found',
        'dmarc': 'not found',
        'raw'  : auth_results
    }

    if auth_results:
        spf_match = re.search(r'spf=(\S+)', auth_results, re.IGNORECASE)
        if spf_match:
            auth['spf'] = spf_match.group(1).rstrip(';')

        dkim_match = re.search(r'dkim=(\S+)', auth_results, re.IGNORECASE)
        if dkim_match:
            auth['dkim'] = dkim_match.group(1).rstrip(';')

        dmarc_match = re.search(r'dmarc=(\S+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            auth['dmarc'] = dmarc_match.group(1).rstrip(';')

    spf_icon   = "PASS" if 'pass' in auth['spf'].lower()   else "FAIL"
    dkim_icon  = "PASS" if 'pass' in auth['dkim'].lower()  else "FAIL"
    dmarc_icon = "PASS" if 'pass' in auth['dmarc'].lower() else "FAIL"

    print(f"  [SPF]   {spf_icon:<6} {auth['spf']}")
    print(f"  [DKIM]  {dkim_icon:<6} {auth['dkim']}")
    print(f"  [DMARC] {dmarc_icon:<6} {auth['dmarc']}")
    print("")

    return auth


def score_phishing_indicators(fields, auth):
    print("-------------------------------------------------------------")
    print("  MODULE 4 -- Phishing Indicator Scoring")
    print("-------------------------------------------------------------")

    score    = 0
    findings = []

    if 'fail' in auth['spf'].lower() or 'softfail' in auth['spf'].lower():
        score += 25
        findings.append("[+25] SPF FAIL  sending IP not authorized for claimed domain")

    if 'none' in auth['dkim'].lower() or 'fail' in auth['dkim'].lower():
        score += 20
        findings.append("[+20] DKIM FAIL/NONE  no cryptographic email signature")

    if 'fail' in auth['dmarc'].lower():
        score += 25
        findings.append("[+25] DMARC FAIL  email authentication policy violated")

    from_domain    = re.search(r'@([\w\.-]+)', fields['from'] or '')
    replyto_domain = re.search(r'@([\w\.-]+)', fields['reply_to'] or '')
    if from_domain and replyto_domain:
        if from_domain.group(1).lower() != replyto_domain.group(1).lower():
            score += 20
            findings.append(f"[+20] Reply-To domain mismatch  From: {from_domain.group(1)} vs Reply-To: {replyto_domain.group(1)}")

    returnpath_domain = re.search(r'@([\w\.-]+)', fields['return_path'] or '')
    if from_domain and returnpath_domain:
        if from_domain.group(1).lower() != returnpath_domain.group(1).lower():
            score += 15
            findings.append(f"[+15] Return-Path domain mismatch  From: {from_domain.group(1)} vs Return-Path: {returnpath_domain.group(1)}")

    x_mailer = (fields['x_mailer'] or '').lower()
    for mailer in SUSPICIOUS_MAILERS:
        if mailer in x_mailer:
            score += 10
            findings.append(f"[+10] Suspicious X-Mailer detected: {fields['x_mailer']}")
            break

    if fields['x_spam_flag'] and 'yes' in fields['x_spam_flag'].lower():
        score += 15
        findings.append("[+15] X-Spam-Flag: YES  spam filter flagged this email")

    if score >= 60:
        verdict = "HIGH RISK -- likely phishing"
    elif score >= 30:
        verdict = "MODERATE RISK -- suspicious, investigate further"
    else:
        verdict = "LOW RISK -- appears legitimate"

    print(f"  [INFO] Phishing indicators found: {len(findings)}")
    print("")
    for f in findings:
        print(f"  {f}")
    print("")
    print(f"  [SCORE]   {score}/130")
    print(f"  [VERDICT] {verdict}")
    print("")

    return score, verdict, findings


def generate_report(filepath, fields, auth, score, verdict,
                    findings, output_file=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    lines = [
        "=============================================================",
        "  SMTP-ANALYZER -- PHISHING HEADER ANALYSIS REPORT",
        "  MITRE ATT&CK: T1566 (Phishing)",
        "=============================================================",
        f"  File analyzed    : {filepath}",
        f"  Report generated : {timestamp}",
        f"  Phishing score   : {score}/130",
        f"  Verdict          : {verdict}",
        "=============================================================",
        "",
        "FORENSIC FIELDS",
        "-" * 45,
        f"  From         : {fields['from']}",
        f"  Reply-To     : {fields['reply_to']}",
        f"  Return-Path  : {fields['return_path']}",
        f"  To           : {fields['to']}",
        f"  Subject      : {fields['subject']}",
        f"  Date         : {fields['date']}",
        f"  Message-ID   : {fields['message_id']}",
        f"  X-Mailer     : {fields['x_mailer']}",
        f"  X-Spam-Flag  : {fields['x_spam_flag']}",
        "",
        f"  Received chain ({len(fields['received_chain'])} hops):",
    ]

    for i, hop in enumerate(fields['received_chain'], 1):
        lines.append(f"    Hop {i}: {hop.strip()[:100]}")

    lines += [
        "",
        "AUTHENTICATION RESULTS",
        "-" * 45,
        f"  SPF   : {auth['spf']}",
        f"  DKIM  : {auth['dkim']}",
        f"  DMARC : {auth['dmarc']}",
        "",
        "PHISHING INDICATORS",
        "-" * 45,
    ]

    for f in findings:
        lines.append(f"  {f}")

    lines += [
        "",
        f"  Total score : {score}/130",
        f"  Verdict     : {verdict}",
        "",
        "ANALYST NOTES",
        "-" * 45,
        "  Analysis conducted on raw email headers only.",
        "  T1566 defender action: block sender domain at email gateway,",
        "  quarantine similar messages, alert user, submit IOCs to threat intel.",
        "",
        "=============================================================",
        "  END OF REPORT",
        "=============================================================",
    ]

    report_text = "\n".join(lines)

    print("-------------------------------------------------------------")
    print("  MODULE 5 -- Phishing Analysis Report")
    print("-------------------------------------------------------------")
    print(report_text)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(report_text)
        print(f"\n[INFO] Report saved to: {output_file}")

    return report_text


def main():
    print(BANNER)
    args = parse_args()

    print(f"[INFO] Analyzing file  : {args.file}")
    print(f"[INFO] Scan started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[INFO] Output file     : {args.output or 'terminal only'}")
    print("")

    print("-------------------------------------------------------------")
    print("  MODULE 1 -- Email Header Parser")
    print("-------------------------------------------------------------")
    msg = load_email(args.file)
    print(f"  [INFO] File loaded successfully")
    print(f"  [INFO] Content-Type  : {msg.get_content_type()}")
    print("")

    fields               = extract_forensic_fields(msg)
    auth                 = check_authentication(msg)
    score, verdict, findings = score_phishing_indicators(fields, auth)
    generate_report(args.file, fields, auth, score,
                    verdict, findings, args.output)


if __name__ == "__main__":
    main()

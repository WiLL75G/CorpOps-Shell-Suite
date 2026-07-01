#!/usr/bin/env python3
###############################################################################
# whois-guard.py
#
# Purpose:  Domain spoofing detection tool  generates typosquat variants
#           of a legitimate domain, queries WHOIS for each, and flags
#           recently registered lookalikes as phishing infrastructure risk.
# Author:   James Williams (WiLL75G)
# Project:  CorpOps Shell Suite / Project 06 - Whois Guard
# MITRE:    T1566 - Phishing
#
# Usage:    python3 whois-guard.py -d <domain>
# Example:  python3 whois-guard.py -d google.com
###############################################################################

import argparse
import whois
import time
from datetime import datetime, timezone

BANNER = """
=============================================================
  WHOIS-GUARD -- CorpOps SOC Tier 1
  Domain Spoofing Detection Tool
  MITRE ATT&CK: T1566 (Phishing)
=============================================================
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Whois-Guard: Domain spoofing detection tool"
    )
    parser.add_argument("-d", "--domain", required=True,
                        help="Legitimate domain to protect (e.g. google.com)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save report to file (optional)")
    parser.add_argument("--days", type=int, default=180,
                        help="Flag domains registered within this many days as high risk (default: 180)")
    return parser.parse_args()


def extract_parts(domain):
    parts = domain.rsplit('.', 1)
    name = parts[0]
    tld  = parts[1] if len(parts) > 1 else 'com'
    return name, tld


def generate_variants(name, tld):
    variants = set()

    substitutions = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1', 'l'],
        'o': ['0'],
        's': ['5', '$'],
        'l': ['1'],
        'g': ['9'],
    }

    for i, char in enumerate(name):
        if char.lower() in substitutions:
            for sub in substitutions[char.lower()]:
                variant = name[:i] + sub + name[i+1:]
                variants.add(f"{variant}.{tld}")

    for i in range(len(name)):
        variant = name[:i] + name[i+1:]
        if len(variant) > 2:
            variants.add(f"{variant}.{tld}")

    for i in range(len(name) - 1):
        variant = name[:i] + name[i+1] + name[i] + name[i+2:]
        variants.add(f"{variant}.{tld}")

    additions = ['s', '-support', '-help', '-login', '-secure', '-verify']
    for add in additions:
        variants.add(f"{name}{add}.{tld}")

    alt_tlds = ['net', 'org', 'co', 'info', 'biz']
    for alt in alt_tlds:
        if alt != tld:
            variants.add(f"{name}.{alt}")

    original = f"{name}.{tld}"
    variants.discard(original)

    return sorted(variants)


def check_whois(domain, days_threshold):
    result = {
        "domain"      : domain,
        "registered"  : False,
        "created"     : None,
        "registrar"   : None,
        "days_old"    : None,
        "risk"        : "UNREGISTERED",
    }

    try:
        w = whois.whois(domain)

        if not w or not w.domain_name:
            return result

        result["registered"] = True
        result["registrar"]  = w.registrar or "Unknown"

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            now      = datetime.now(timezone.utc)
            days_old = (now - created).days
            result["created"]  = created.strftime('%Y-%m-%d')
            result["days_old"] = days_old

            if days_old <= days_threshold:
                result["risk"] = "HIGH RISK"
            else:
                result["risk"] = "MODERATE RISK"
        else:
            result["risk"] = "MODERATE RISK"

    except Exception:
        pass

    return result


def run_scan(domain, days_threshold):
    name, tld = extract_parts(domain)
    variants  = generate_variants(name, tld)

    print("-------------------------------------------------------------")
    print("  MODULE 1 -- Typosquat Variant Generation")
    print("-------------------------------------------------------------")
    print(f"  [INFO] Legitimate domain : {domain}")
    print(f"  [INFO] Variants generated: {len(variants)}")
    print("")

    print("-------------------------------------------------------------")
    print("  MODULE 2 -- WHOIS Lookup + MODULE 3 -- Risk Scoring")
    print("-------------------------------------------------------------")
    print(f"  [INFO] Flagging domains registered within {days_threshold} days as HIGH RISK")
    print("")

    results = []
    for variant in variants:
        result = check_whois(variant, days_threshold)
        results.append(result)

        if result["registered"]:
            risk  = result["risk"]
            label = f"[{risk}]"
            print(f"  {label:<18} {variant}")
            print(f"               Created  : {result['created']} ({result['days_old']} days ago)")
            print(f"               Registrar: {result['registrar']}")
            print("")
        time.sleep(0.5)

    return results


def generate_report(domain, results, days_threshold, output_file=None):
    timestamp  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    registered = [r for r in results if r["registered"]]
    high_risk  = [r for r in registered if r["risk"] == "HIGH RISK"]
    moderate   = [r for r in registered if r["risk"] == "MODERATE RISK"]

    lines = [
        "=============================================================",
        "  WHOIS-GUARD -- DOMAIN SPOOFING DETECTION REPORT",
        "  MITRE ATT&CK: T1566 (Phishing)",
        "=============================================================",
        f"  Legitimate domain : {domain}",
        f"  Report generated  : {timestamp}",
        f"  High-risk window  : {days_threshold} days",
        "=============================================================",
        "",
        "SCAN SUMMARY",
        "-" * 45,
        f"  Variants checked  : {len(results)}",
        f"  Registered domains: {len(registered)}",
        f"  HIGH RISK         : {len(high_risk)}",
        f"  MODERATE RISK     : {len(moderate)}",
        f"  Unregistered      : {len(results) - len(registered)}",
        "",
    ]

    if high_risk:
        lines.append("HIGH RISK DOMAINS (registered within threshold)")
        lines.append("-" * 45)
        for r in high_risk:
            lines.append(f"  [!] {r['domain']}")
            lines.append(f"      Created  : {r['created']} ({r['days_old']} days ago)")
            lines.append(f"      Registrar: {r['registrar']}")
            lines.append("")

    if moderate:
        lines.append("MODERATE RISK DOMAINS")
        lines.append("-" * 45)
        for r in moderate:
            lines.append(f"  [~] {r['domain']}")
            lines.append(f"      Created  : {r['created']} ({r['days_old']} days ago)")
            lines.append(f"      Registrar: {r['registrar']}")
            lines.append("")

    lines += [
        "ANALYST NOTES",
        "-" * 45,
        "  WHOIS lookups conducted passively against public registration data.",
        "  HIGH RISK = registered AND created within the threshold window.",
        "  T1566 defender action: block HIGH RISK domains at email gateway",
        "  and proxy, report to domain registrar, alert users.",
        "",
        "=============================================================",
        "  END OF REPORT",
        "=============================================================",
    ]

    report_text = "\n".join(lines)

    print("-------------------------------------------------------------")
    print("  MODULE 4 -- Domain Spoofing Report")
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

    print(f"[INFO] Target domain   : {args.domain}")
    print(f"[INFO] Scan started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[INFO] Risk threshold  : {args.days} days")
    print(f"[INFO] Output file     : {args.output or 'terminal only'}")
    print("")

    results = run_scan(args.domain, args.days)
    generate_report(args.domain, results, args.days, args.output)


if __name__ == "__main__":
    main()

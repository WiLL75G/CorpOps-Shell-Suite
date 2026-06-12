#!/usr/bin/env python3
###############################################################################
# user-scanner.py
#
# Purpose:  Email and username OSINT tool — validates email addresses,
#           analyses the domain behind them, extracts the username, checks
#           platform presence, and generates targeted dork queries.
# Author:   James Williams (WiLL75G)
# Project:  CorpOps Shell Suite / Project 04 - User-Scanner
# MITRE:    T1589 - Gather Victim Identity Information
#
# Usage:    python3 user-scanner.py -e <email>
# Example:  python3 user-scanner.py -e james@gmail.com
###############################################################################

import argparse
import re
import requests
import dns.resolver
from datetime import datetime

BANNER = """
=============================================================
  USER-SCANNER -- CorpOps SOC Tier 1
  Email & Username OSINT Tool
  MITRE ATT&CK: T1589 (Gather Victim Identity Information)
=============================================================
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="User-Scanner: Email and username OSINT tool"
    )
    parser.add_argument("-e", "--email", required=True,
                        help="Target email address to investigate")
    parser.add_argument("-o", "--output", default=None,
                        help="Save report to file (optional)")
    return parser.parse_args()


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def extract_parts(email):
    username = email.split('@')[0]
    domain   = email.split('@')[1]
    return username, domain


def analyse_domain(domain):
    print("-------------------------------------------------------------")
    print("  MODULE 1 -- Email Domain Analysis (MX Records)")
    print("-------------------------------------------------------------")
    results = {"domain": domain, "mx_records": [], "provider": "Unknown"}
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        sorted_mx  = sorted(mx_records, key=lambda r: r.preference)
        print(f"  [INFO] Domain          : {domain}")
        print(f"  [INFO] MX records found: {len(sorted_mx)}")
        print("")
        for record in sorted_mx:
            mx_host = str(record.exchange).rstrip('.')
            print(f"  [MX]  Priority {record.preference:<5} {mx_host}")
            results["mx_records"].append({"priority": record.preference, "host": mx_host})
        primary_mx = str(sorted_mx[0].exchange).lower()
        if "google" in primary_mx or "gmail" in primary_mx:
            results["provider"] = "Google Workspace / Gmail"
        elif "outlook" in primary_mx or "microsoft" in primary_mx:
            results["provider"] = "Microsoft 365 / Outlook"
        elif "mimecast" in primary_mx:
            results["provider"] = "Mimecast (email security gateway)"
        elif "proofpoint" in primary_mx:
            results["provider"] = "Proofpoint (email security gateway)"
        elif "mailgun" in primary_mx:
            results["provider"] = "Mailgun"
        else:
            results["provider"] = f"Unknown/Custom ({primary_mx})"
        print("")
        print(f"  [PROVIDER] {results['provider']}")
    except dns.resolver.NXDOMAIN:
        print(f"  [ERROR] Domain {domain} does not exist.")
        results["provider"] = "NXDOMAIN - domain not found"
    except dns.resolver.NoAnswer:
        print(f"  [ERROR] No MX records found for {domain}.")
        results["provider"] = "No MX records"
    except Exception as e:
        print(f"  [ERROR] DNS lookup failed: {e}")
    print("")
    return results


def check_platforms(username):
    platforms = {
        "GitHub"     : f"https://github.com/{username}",
        "GitLab"     : f"https://gitlab.com/{username}",
        "Reddit"     : f"https://www.reddit.com/user/{username}",
        "HackerNews" : f"https://news.ycombinator.com/user?id={username}",
        "Dev.to"     : f"https://dev.to/{username}",
        "Medium"     : f"https://medium.com/@{username}",
        "Keybase"    : f"https://keybase.io/{username}",
        "TryHackMe"  : f"https://tryhackme.com/p/{username}",
    }
    print("-------------------------------------------------------------")
    print("  MODULE 2 -- Platform Presence (derived username)")
    print("-------------------------------------------------------------")
    results = {}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; user-scanner/1.0)"}
    for platform, url in platforms.items():
        try:
            r = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
            if r.status_code == 200:
                print(f"  [FOUND]     {platform:<15} {url}")
                results[platform] = {"url": url, "status": "FOUND"}
            else:
                print(f"  [NOT FOUND] {platform:<15} (HTTP {r.status_code})")
                results[platform] = {"url": url, "status": "NOT FOUND"}
        except requests.exceptions.Timeout:
            print(f"  [TIMEOUT]   {platform:<15}")
            results[platform] = {"url": url, "status": "TIMEOUT"}
        except requests.exceptions.ConnectionError:
            print(f"  [ERROR]     {platform:<15} (connection failed)")
            results[platform] = {"url": url, "status": "ERROR"}
    print("")
    return results


def generate_dorks(email, username, domain):
    dorks = [
        f'"{email}"',
        f'"{email}" site:pastebin.com',
        f'"{email}" site:github.com',
        f'"{email}" intext:"password" OR intext:"credentials"',
        f'"{email}" "API key" OR "access token" OR "secret"',
        f'"{username}" site:{domain}',
        f'"{username}" site:linkedin.com',
        f'site:{domain} intext:"@{domain}"',
        f'site:{domain} filetype:pdf OR filetype:doc',
        f'"{domain}" email list OR staff OR employees',
    ]
    print("-------------------------------------------------------------")
    print("  MODULE 3 -- Targeted Dork Queries")
    print("  (copy and run manually in a browser)")
    print("-------------------------------------------------------------")
    for i, dork in enumerate(dorks, 1):
        print(f"  [{i:02d}] {dork}")
    print("")
    return dorks


def generate_report(email, username, domain, domain_results,
                    platform_results, dork_results, output_file=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    found     = [p for p, r in platform_results.items() if r['status'] == 'FOUND']
    not_found = [p for p, r in platform_results.items() if r['status'] == 'NOT FOUND']
    errors    = [p for p, r in platform_results.items() if r['status'] in ('TIMEOUT', 'ERROR')]
    lines = [
        "=============================================================",
        "  USER-SCANNER -- EMAIL & USERNAME OSINT REPORT",
        "  MITRE ATT&CK: T1589 (Gather Victim Identity Information)",
        "=============================================================",
        f"  Target email     : {email}",
        f"  Username         : {username}",
        f"  Domain           : {domain}",
        f"  Report generated : {timestamp}",
        "=============================================================",
        "",
        "EMAIL DOMAIN ANALYSIS",
        "-" * 45,
        f"  Domain    : {domain}",
        f"  Provider  : {domain_results.get('provider', 'Unknown')}",
        f"  MX records: {len(domain_results.get('mx_records', []))} found",
        "",
    ]
    for mx in domain_results.get("mx_records", []):
        lines.append(f"  [MX] Priority {mx['priority']:<5} {mx['host']}")
    lines.append("")
    lines += [
        "PLATFORM PRESENCE SUMMARY",
        "-" * 45,
        f"  Platforms checked : {len(platform_results)}",
        f"  Profiles found    : {len(found)}",
        f"  Not found         : {len(not_found)}",
        f"  Errors/timeouts   : {len(errors)}",
        "",
    ]
    if found:
        lines.append("CONFIRMED PROFILES")
        lines.append("-" * 45)
        for platform in found:
            lines.append(f"  [+] {platform:<15} {platform_results[platform]['url']}")
        lines.append("")
    lines.append("TARGETED DORK QUERIES")
    lines.append("-" * 45)
    for i, dork in enumerate(dork_results, 1):
        lines.append(f"  [{i:02d}] {dork}")
    lines.append("")
    lines += [
        "ANALYST NOTES",
        "-" * 45,
        "  Audit conducted passively. No authentication or exploitation used.",
        "  T1589 defender action: review exposure, harden email settings,",
        "  run credential dorks manually, monitor confirmed platforms.",
        "",
        "=============================================================",
        "  END OF REPORT",
        "=============================================================",
    ]
    report_text = "\n".join(lines)
    print("-------------------------------------------------------------")
    print("  MODULE 4 -- Email & Username OSINT Report")
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
    print(f"[INFO] Target email    : {args.email}")
    print(f"[INFO] Scan started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[INFO] Output file     : {args.output or 'terminal only'}")
    print("")
    if not validate_email(args.email):
        print("[ERROR] Invalid email format. Exiting.")
        exit(1)
    username, domain = extract_parts(args.email)
    print(f"[INFO] Username extracted : {username}")
    print(f"[INFO] Domain extracted   : {domain}")
    print("")
    domain_results   = analyse_domain(domain)
    platform_results = check_platforms(username)
    dork_results     = generate_dorks(args.email, username, domain)
    generate_report(args.email, username, domain,
                    domain_results, platform_results,
                    dork_results, args.output)


if __name__ == "__main__":
    main()

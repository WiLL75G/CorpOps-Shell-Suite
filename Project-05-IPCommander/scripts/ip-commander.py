#!/usr/bin/env python3
###############################################################################
# ip-commander.py
#
# Purpose:  Threat intelligence enrichment tool  takes an IP address and
#           returns geolocation, abuse reputation, and reverse DNS data in
#           a single structured report.
# Author:   James Williams (WiLL75G)
# Project:  CorpOps Shell Suite / Project 05 - IP Commander
# MITRE:    T1071 - Application Layer Protocol
#
# Usage:    python3 ip-commander.py -i <ip_address>
# Example:  python3 ip-commander.py -i 8.8.8.8
#
# Requires: ABUSEIPDB_KEY environment variable set (see README for setup)
###############################################################################

import argparse
import os
import socket
import requests
from datetime import datetime

BANNER = """
=============================================================
  IP-COMMANDER -- CorpOps SOC Tier 1
  Threat Intelligence Enrichment Tool
  MITRE ATT&CK: T1071 (Application Layer Protocol)
=============================================================
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="IP-Commander: Threat intel enrichment tool"
    )
    parser.add_argument("-i", "--ip", required=True,
                        help="Target IP address to investigate")
    parser.add_argument("-o", "--output", default=None,
                        help="Save report to file (optional)")
    return parser.parse_args()


def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def geolocate_ip(ip):
    print("-------------------------------------------------------------")
    print("  MODULE 1 -- Geolocation (ip-api.com)")
    print("-------------------------------------------------------------")
    results = {"status": "fail"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        data = r.json()
        if data.get("status") == "success":
            results = data
            print(f"  [INFO] IP        : {ip}")
            print(f"  [INFO] Country   : {data.get('country', 'Unknown')}")
            print(f"  [INFO] City      : {data.get('city', 'Unknown')}")
            print(f"  [INFO] ISP       : {data.get('isp', 'Unknown')}")
            print(f"  [INFO] ASN/Org   : {data.get('org', 'Unknown')}")
        else:
            print(f"  [ERROR] Geolocation failed: {data.get('message', 'Unknown error')}")
    except Exception as e:
        print(f"  [ERROR] Geolocation request failed: {e}")
    print("")
    return results


def check_abuse_reputation(ip):
    print("-------------------------------------------------------------")
    print("  MODULE 2 -- Abuse Reputation (AbuseIPDB)")
    print("-------------------------------------------------------------")
    results = {"abuseConfidenceScore": None, "totalReports": None}
    api_key = os.environ.get("ABUSEIPDB_KEY")

    if not api_key:
        print("  [ERROR] ABUSEIPDB_KEY environment variable not set.")
        print("  [INFO]  Skipping abuse reputation check.")
        print("")
        return results

    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=headers, params=params, timeout=8)
        data = r.json().get("data", {})
        results = data
        score   = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        print(f"  [INFO] Abuse confidence score : {score}/100")
        print(f"  [INFO] Total reports          : {reports}")
        print(f"  [INFO] Last reported          : {data.get('lastReportedAt', 'Never')}")
        print(f"  [INFO] Is whitelisted         : {data.get('isWhitelisted', False)}")

        if score >= 75:
            print("  [VERDICT] HIGH RISK -- known malicious activity reported")
        elif score >= 25:
            print("  [VERDICT] MODERATE RISK -- some abuse reports on record")
        else:
            print("  [VERDICT] LOW RISK -- minimal or no abuse history")

    except Exception as e:
        print(f"  [ERROR] AbuseIPDB request failed: {e}")
    print("")
    return results


def reverse_dns(ip):
    print("-------------------------------------------------------------")
    print("  MODULE 3 -- Reverse DNS Lookup")
    print("-------------------------------------------------------------")
    results = {"hostname": None}
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        results["hostname"] = hostname
        print(f"  [INFO] Hostname : {hostname}")
    except socket.herror:
        print(f"  [INFO] No reverse DNS record found for {ip}")
    except Exception as e:
        print(f"  [ERROR] Reverse DNS lookup failed: {e}")
    print("")
    return results


def generate_report(ip, geo_results, abuse_results, dns_results, output_file=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    score = abuse_results.get("abuseConfidenceScore")
    if score is None:
        verdict = "UNKNOWN (AbuseIPDB unavailable)"
    elif score >= 75:
        verdict = "HIGH RISK"
    elif score >= 25:
        verdict = "MODERATE RISK"
    else:
        verdict = "LOW RISK"

    lines = [
        "=============================================================",
        "  IP-COMMANDER -- THREAT INTELLIGENCE ENRICHMENT REPORT",
        "  MITRE ATT&CK: T1071 (Application Layer Protocol)",
        "=============================================================",
        f"  Target IP        : {ip}",
        f"  Report generated : {timestamp}",
        f"  Overall verdict  : {verdict}",
        "=============================================================",
        "",
        "GEOLOCATION",
        "-" * 45,
        f"  Country  : {geo_results.get('country', 'Unknown')}",
        f"  City     : {geo_results.get('city', 'Unknown')}",
        f"  ISP      : {geo_results.get('isp', 'Unknown')}",
        f"  ASN/Org  : {geo_results.get('org', 'Unknown')}",
        "",
        "ABUSE REPUTATION (AbuseIPDB)",
        "-" * 45,
        f"  Confidence score : {abuse_results.get('abuseConfidenceScore', 'N/A')}/100",
        f"  Total reports    : {abuse_results.get('totalReports', 'N/A')}",
        f"  Last reported    : {abuse_results.get('lastReportedAt', 'Never')}",
        "",
        "REVERSE DNS",
        "-" * 45,
        f"  Hostname : {dns_results.get('hostname') or 'No PTR record found'}",
        "",
        "ANALYST NOTES",
        "-" * 45,
        "  Enrichment conducted via passive lookups only.",
        "  T1071 defender action: cross-reference against SIEM logs,",
        "  correlate timing with other IOCs, escalate if verdict is HIGH RISK.",
        "",
        "=============================================================",
        "  END OF REPORT",
        "=============================================================",
    ]

    report_text = "\n".join(lines)
    print("-------------------------------------------------------------")
    print("  MODULE 4 -- Threat Intelligence Report")
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

    print(f"[INFO] Target IP       : {args.ip}")
    print(f"[INFO] Scan started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[INFO] Output file     : {args.output or 'terminal only'}")
    print("")

    if not validate_ip(args.ip):
        print("[ERROR] Invalid IP address format. Exiting.")
        exit(1)

    geo_results   = geolocate_ip(args.ip)
    abuse_results = check_abuse_reputation(args.ip)
    dns_results   = reverse_dns(args.ip)
    generate_report(args.ip, geo_results, abuse_results, dns_results, args.output)


if __name__ == "__main__":
    main()

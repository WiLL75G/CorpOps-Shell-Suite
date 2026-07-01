#!/usr/bin/env python3
###############################################################################
# eternalview.py
#
# Purpose:  Active reconnaissance and defense mapping tool  scans a target,
#           grabs service banners, fingerprints the OS, and maps every finding
#           to a MITRE ATT&CK technique and a defensive recommendation.
# Author:   James Williams (WiLL75G)
# Project:  CorpOps Shell Suite / Project 07 - EternalView
# MITRE:    T1595 - Active Scanning
#
# Usage:    sudo python3 eternalview.py -t <target_ip>
# Example:  sudo python3 eternalview.py -t 192.168.64.12
#
# Note:     Requires sudo for SYN scan. Run only against authorized targets.
###############################################################################

import argparse
import nmap
import socket
from datetime import datetime

BANNER = """
=============================================================
  ETERNALVIEW -- CorpOps SOC Tier 1
  Recon & Defense Mapping Tool
  MITRE ATT&CK: T1595 (Active Scanning)
=============================================================
"""

MITRE_MAP = {
    21  : ("T1021.002", "File Transfer Protocols",
           "Disable FTP if unused. Use SFTP instead. Restrict with firewall."),
    22  : ("T1021.004", "Remote Services: SSH",
           "Enforce key-only auth. Disable root login. Deploy fail2ban."),
    23  : ("T1021.001", "Remote Services: Telnet",
           "Disable Telnet immediately. Replace with SSH."),
    25  : ("T1566.001", "Phishing via SMTP",
           "Restrict relay. Enable SPF/DKIM/DMARC. Monitor for spam."),
    53  : ("T1071.004", "DNS Application Layer Protocol",
           "Restrict zone transfers. Monitor for DNS tunneling."),
    80  : ("T1190",     "Exploit Public-Facing Application (HTTP)",
           "Deploy WAF. Keep web server patched. Disable directory listing."),
    110 : ("T1114",     "Email Collection via POP3",
           "Enforce TLS. Restrict to authorized clients only."),
    139 : ("T1021.002", "SMB/NetBIOS",
           "Block at perimeter. Disable if unused. Monitor for lateral movement."),
    143 : ("T1114",     "Email Collection via IMAP",
           "Enforce TLS. Restrict to authorized clients only."),
    443 : ("T1190",     "Exploit Public-Facing Application (HTTPS)",
           "Keep TLS current. Deploy WAF. Monitor certificate transparency logs."),
    445 : ("T1021.002", "Remote Services: SMB",
           "Block at perimeter if unused. Patch EternalBlue. Require SMB signing."),
    3306: ("T1190",     "Exploit Public-Facing Application (MySQL)",
           "Never expose DB to internet. Restrict to localhost or VPN only."),
    3389: ("T1021.001", "Remote Services: RDP",
           "Enforce NLA. Restrict to VPN. Monitor for brute-force."),
    5900: ("T1021.005", "Remote Services: VNC",
           "Disable if unused. Never expose to internet. Require strong auth."),
    8080: ("T1190",     "Exploit Public-Facing Application (HTTP-alt)",
           "Same as port 80. Verify what service is running here."),
    8443: ("T1190",     "Exploit Public-Facing Application (HTTPS-alt)",
           "Same as port 443. Verify what service is running here."),
}

DEFAULT_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080,8443"


def parse_args():
    parser = argparse.ArgumentParser(
        description="EternalView: Recon and defense mapping tool"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP address (authorized targets only)")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                        help=f"Ports to scan (default: {DEFAULT_PORTS})")
    parser.add_argument("-o", "--output", default=None,
                        help="Save report to file (optional)")
    return parser.parse_args()


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def run_port_scan(target, ports):
    print("-------------------------------------------------------------")
    print("  MODULE 1 -- TCP Port Scan")
    print("-------------------------------------------------------------")
    print(f"  [INFO] Target  : {target}")
    print(f"  [INFO] Ports   : {ports}")
    print("")

    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=ports, arguments="-sS -sV -O --open")

    open_ports = []

    if target not in nm.all_hosts():
        print("  [ERROR] Host appears down or unreachable.")
        return [], nm

    host = nm[target]

    for proto in host.all_protocols():
        for port in sorted(host[proto].keys()):
            state   = host[proto][port]['state']
            service = host[proto][port]['name']
            product = host[proto][port].get('product', '')
            version = host[proto][port].get('version', '')
            banner  = f"{product} {version}".strip() or "Unknown"

            if state == 'open':
                open_ports.append({
                    "port"   : port,
                    "proto"  : proto,
                    "service": service,
                    "banner" : banner,
                    "state"  : state,
                })
                print(f"  [OPEN]  {port}/{proto:<4} {service:<15} {banner}")

    print("")
    return open_ports, nm


def get_os_fingerprint(nm, target):
    print("-------------------------------------------------------------")
    print("  MODULE 3 -- OS Fingerprint")
    print("-------------------------------------------------------------")

    os_guess = "Unknown"
    try:
        if 'osmatch' in nm[target] and nm[target]['osmatch']:
            top = nm[target]['osmatch'][0]
            os_guess = f"{top['name']} (accuracy: {top['accuracy']}%)"
    except Exception:
        pass

    print(f"  [INFO] OS guess: {os_guess}")
    print("")
    return os_guess


def map_to_mitre(open_ports):
    print("-------------------------------------------------------------")
    print("  MODULE 4 -- MITRE ATT&CK Mapping & Defense Recommendations")
    print("-------------------------------------------------------------")

    mappings = []

    for entry in open_ports:
        port    = entry["port"]
        service = entry["service"]
        banner  = entry["banner"]

        if port in MITRE_MAP:
            tech_id, tech_name, defense = MITRE_MAP[port]
        else:
            tech_id   = "T1595"
            tech_name = "Active Scanning (unknown service)"
            defense   = "Investigate this service. Block if not required."

        mappings.append({
            "port"     : port,
            "service"  : service,
            "banner"   : banner,
            "tech_id"  : tech_id,
            "tech_name": tech_name,
            "defense"  : defense,
        })

        print(f"  Port {port:<5} {service:<15} -> {tech_id} {tech_name}")
        print(f"           Defense: {defense}")
        print("")

    return mappings


def generate_report(target, hostname, os_guess, open_ports,
                    mappings, output_file=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    lines = [
        "=============================================================",
        "  ETERNALVIEW -- RECON & DEFENSE MAPPING REPORT",
        "  MITRE ATT&CK: T1595 (Active Scanning)",
        "=============================================================",
        f"  Target IP        : {target}",
        f"  Hostname         : {hostname}",
        f"  OS Fingerprint   : {os_guess}",
        f"  Report generated : {timestamp}",
        "=============================================================",
        "",
        "PORT SCAN SUMMARY",
        "-" * 45,
        f"  Open ports found : {len(open_ports)}",
        "",
    ]

    if open_ports:
        lines.append("OPEN PORTS")
        lines.append("-" * 45)
        for p in open_ports:
            lines.append(f"  {p['port']}/{p['proto']:<4} {p['service']:<15} {p['banner']}")
        lines.append("")

    lines.append("MITRE ATT&CK MAPPING & DEFENSE RECOMMENDATIONS")
    lines.append("-" * 45)

    for m in mappings:
        lines.append(f"  Port    : {m['port']} ({m['service']})")
        lines.append(f"  Banner  : {m['banner']}")
        lines.append(f"  MITRE   : {m['tech_id']} -- {m['tech_name']}")
        lines.append(f"  Defense : {m['defense']}")
        lines.append("")

    lines += [
        "ANALYST NOTES",
        "-" * 45,
        "  Scan conducted against authorized lab target only.",
        "  All findings mapped to MITRE ATT&CK T1595 (Active Scanning).",
        "  T1595 defender action: close unnecessary ports, harden exposed",
        "  services, verify all banners match expected software versions.",
        "",
        "=============================================================",
        "  END OF REPORT",
        "=============================================================",
    ]

    report_text = "\n".join(lines)

    print("-------------------------------------------------------------")
    print("  MODULE 5 -- Recon & Defense Report")
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

    hostname = resolve_hostname(args.target)

    print(f"[INFO] Target IP       : {args.target}")
    print(f"[INFO] Hostname        : {hostname}")
    print(f"[INFO] Scan started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[INFO] Output file     : {args.output or 'terminal only'}")
    print("")

    open_ports, nm = run_port_scan(args.target, args.ports)

    print("-------------------------------------------------------------")
    print("  MODULE 2 -- Service Banner Summary")
    print("-------------------------------------------------------------")
    for p in open_ports:
        print(f"  Port {p['port']:<5} Banner: {p['banner']}")
    print("")

    os_guess = get_os_fingerprint(nm, args.target)
    mappings = map_to_mitre(open_ports)
    generate_report(args.target, hostname, os_guess,
                    open_ports, mappings, args.output)


if __name__ == "__main__":
    main()

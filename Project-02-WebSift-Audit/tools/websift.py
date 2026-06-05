#!/usr/bin/env python3
"""
WebSift - Public Web Asset & Footprint Auditor
================================================
A defensive (blue-team) OSINT tool that audits the PUBLIC footprint of a
single web target. It only reads information the target already serves to
any browser - no authentication, no exploitation, no brute-forcing.

MITRE ATT&CK mapping: T1593 - Search Open Websites/Domains (defensive use).

Author : James Williams (github.com/WiLL75G)
Project: CorpOps Shell Suite - Project 02
Modules: 1 Fetch Core | 2 Header Fingerprint | 3 robots/sitemap | 4 Security Headers
"""

import argparse
import sys
from urllib.parse import urljoin
import requests


class WebSift:
    """Fetch the target once, then run analysis modules against it."""

    HEADERS = {
        "User-Agent": "WebSift/1.0 (+https://github.com/WiLL75G; defensive-footprint-audit)"
    }
    TIMEOUT = 10

    TECH_LEAK_HEADERS = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Generator", "X-Drupal-Cache", "X-Runtime", "Via",
    ]

    # Security headers a hardened site SHOULD send. Absence is the finding.
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "Forces HTTPS (prevents SSL-strip/downgrade).",
        "Content-Security-Policy":  "Restricts resource loading (mitigates XSS).",
        "X-Frame-Options":          "Prevents framing (mitigates clickjacking).",
        "X-Content-Type-Options":   "Stops MIME-sniffing.",
        "Referrer-Policy":          "Controls referrer leakage to other sites.",
        "Permissions-Policy":       "Restricts powerful browser features.",
    }

    def __init__(self, target_url):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url
        self.response = None

    # ------------------------------------------------------------------ #
    # MODULE 1 - HTTP Fetch Core                                          #
    # ------------------------------------------------------------------ #
    def fetch(self):
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Fetching (timeout {self.TIMEOUT}s)...")
        try:
            self.response = requests.get(
                self.target_url, headers=self.HEADERS,
                timeout=self.TIMEOUT, allow_redirects=True,
            )
        except requests.exceptions.Timeout:
            print(f"[!] ERROR: request timed out after {self.TIMEOUT}s.")
            return False
        except requests.exceptions.ConnectionError:
            print("[!] ERROR: could not connect to target (DNS / network / host down).")
            return False
        except requests.exceptions.RequestException as e:
            print(f"[!] ERROR: request failed: {e}")
            return False

        print(f"[+] Connected. HTTP status: {self.response.status_code}")
        if self.response.history:
            print(f"[+] Followed {len(self.response.history)} redirect(s) to final URL: {self.response.url}")
        return True

    # ------------------------------------------------------------------ #
    # MODULE 2 - Header & Technology Fingerprinting                       #
    # ------------------------------------------------------------------ #
    def fingerprint_headers(self):
        print("\n" + "-" * 60)
        print("  MODULE 2: Header & Technology Fingerprinting")
        print("-" * 60)
        if self.response is None:
            print("[!] No response to analyse. Run fetch() first.")
            return

        headers = self.response.headers
        findings = []
        for name in self.TECH_LEAK_HEADERS:
            if name in headers:
                value = headers[name]
                leaks_version = any(ch.isdigit() for ch in value)
                findings.append((name, value, leaks_version))

        if not findings:
            print("[+] GOOD: no obvious technology-leaking headers found.")
            print("    The target is not volunteering server/stack details.")
            return

        print(f"[!] Found {len(findings)} technology-disclosing header(s):\n")
        for name, value, leaks_version in findings:
            flag = "  <-- DISCLOSES VERSION" if leaks_version else ""
            print(f"    {name}: {value}{flag}")

        version_leaks = [f for f in findings if f[2]]
        if version_leaks:
            print(f"\n[!] RISK: {len(version_leaks)} header(s) disclose version numbers.")
            print("    Recommendation: suppress or genericise these headers so")
            print("    attackers cannot map exact versions to known CVEs.")

    # ------------------------------------------------------------------ #
    # MODULE 3 - robots.txt & sitemap.xml Parsing                         #
    # ------------------------------------------------------------------ #
    def _get_public_file(self, path):
        url = urljoin(self.target_url, path)
        try:
            r = requests.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
        except requests.exceptions.RequestException:
            return None
        if r.status_code == 200 and r.text.strip():
            return r.text
        return None

    def parse_robots_sitemap(self):
        print("\n" + "-" * 60)
        print("  MODULE 3: robots.txt & sitemap.xml Parsing")
        print("-" * 60)

        robots = self._get_public_file("/robots.txt")
        if robots is None:
            print("[+] No robots.txt found (or empty).")
        else:
            print("[!] robots.txt found. Contents disclose crawl rules:\n")
            disallowed = []
            for line in robots.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                        print(f"    Disallow: {path}")
            if disallowed:
                print(f"\n[!] RISK: {len(disallowed)} path(s) listed as Disallow.")
                print("    These are paths the owner did not want indexed - but")
                print("    robots.txt is PUBLIC, so it can act as a map to")
                print("    sensitive locations for an attacker.")
            else:
                print("    (No Disallow entries - robots.txt discloses little.)")

        sitemap = self._get_public_file("/sitemap.xml")
        if sitemap is None:
            print("\n[+] No sitemap.xml found (or empty).")
        else:
            url_count = sitemap.count("<loc>")
            print(f"\n[!] sitemap.xml found. It lists ~{url_count} URL(s),")
            print("    disclosing the intended public structure of the site.")

    # ------------------------------------------------------------------ #
    # MODULE 4 - Security-Header Audit                                    #
    # ------------------------------------------------------------------ #
    def audit_security_headers(self):
        print("\n" + "-" * 60)
        print("  MODULE 4: Security-Header Audit")
        print("-" * 60)
        if self.response is None:
            print("[!] No response to analyse. Run fetch() first.")
            return

        headers = self.response.headers
        present, missing = [], []

        for name, purpose in self.SECURITY_HEADERS.items():
            if name in headers:
                present.append(name)
            else:
                missing.append((name, purpose))

        total = len(self.SECURITY_HEADERS)
        print(f"[*] Security header score: {len(present)}/{total} present.\n")

        if present:
            print("[+] PRESENT (good):")
            for name in present:
                print(f"    + {name}")
            print()

        if missing:
            print("[!] MISSING (hardening opportunities):")
            for name, purpose in missing:
                print(f"    - {name}")
                print(f"        {purpose}")
            print()
            print(f"[!] RISK: {len(missing)} recommended security header(s) absent.")
            print("    Recommendation: add the missing headers at the web server")
            print("    or CDN layer to harden the public footprint.")
        else:
            print("[+] EXCELLENT: all recommended security headers present.")


def main():
    parser = argparse.ArgumentParser(
        description="WebSift - public web footprint auditor (defensive OSINT, MITRE T1593)"
    )
    parser.add_argument("target", help="Target URL, e.g. https://example.com (scheme optional)")
    args = parser.parse_args()

    print("=" * 60)
    print("  WebSift v1.0 - Public Web Footprint Auditor")
    print("  Defensive OSINT | MITRE ATT&CK T1593")
    print("=" * 60)

    sift = WebSift(args.target)
    if not sift.fetch():
        print("[!] Audit aborted: could not retrieve target.")
        sys.exit(1)

    sift.fingerprint_headers()
    sift.parse_robots_sitemap()
    sift.audit_security_headers()

    print("\n" + "=" * 60)
    print("  Audit complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()

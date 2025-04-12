#!/usr/bin/env python3
"""
SiteGuard - Website Security Scanner
A simple tool for scanning websites for common security vulnerabilities
"""

import sys
import argparse
import datetime
from scanner import WebScanner
from xss_detector import XSSDetector
from sqli_detector import SQLiDetector
from path_detector import PathTraversalDetector
from reporter import VulnerabilityReporter
from config import Config

def main():
    parser = argparse.ArgumentParser(
        description='SiteGuard - Website Security Scanner v0.1',
        epilog='Example: python siteguard.py http://example.com -o report.txt'
    )
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('--create-config', help='Create sample configuration file')
    parser.add_argument('-v', '--version', action='version', version='SiteGuard 0.1')

    args = parser.parse_args()

    if args.create_config:
        config = Config()
        config.create_sample_config(args.create_config)
        return

    if not args.url:
        print("Error: URL is required")
        parser.print_help()
        sys.exit(1)

    config = Config()
    if args.config:
        config.load_from_file(args.config)

    print(f"SiteGuard v0.1")
    print(f"Scanning: {args.url}")

    timeout = config.get('timeout', 10)
    scanner = WebScanner(args.url, timeout=timeout)
    reporter = VulnerabilityReporter()
    scan_start = datetime.datetime.now()
    reporter.set_scan_info(args.url, scan_start)

    if not scanner.is_valid_url(args.url):
        print("Error: Invalid URL provided")
        sys.exit(1)

    print("Checking target accessibility...")
    response = scanner.make_request(args.url)
    if response:
        print(f"Target is accessible (Status: {response.status_code})")
    else:
        print("Target is not accessible")
        sys.exit(1)

    print("\n--- Starting XSS Detection ---")
    xss_detector = XSSDetector(scanner)
    forms = xss_detector.find_forms(args.url)

    if forms:
        print(f"Found {len(forms)} form(s) to test")
        for i, form in enumerate(forms):
            print(f"Testing form {i+1}: {form['action']}")
            xss_vulns = xss_detector.test_xss_in_form(form)
            if xss_vulns:
                for vuln in xss_vulns:
                    print(f"  [!] XSS vulnerability found in {vuln['parameter']}")
                    reporter.add_vulnerability(vuln)
            else:
                print("  No XSS vulnerabilities found")
    else:
        print("No forms found for XSS testing")

    print("\n--- Starting SQL Injection Detection ---")
    sqli_detector = SQLiDetector(scanner)
    sqli_forms = sqli_detector.find_input_points(args.url)

    if sqli_forms:
        print(f"Found {len(sqli_forms)} form(s) to test for SQLi")
        for i, form in enumerate(sqli_forms):
            print(f"Testing form {i+1} for SQLi: {form['action']}")
            sqli_vulns = sqli_detector.test_sqli_in_form(form)
            if sqli_vulns:
                for vuln in sqli_vulns:
                    print(f"  [!] SQL Injection found in {vuln['parameter']}")
                    reporter.add_vulnerability(vuln)
            else:
                print("  No SQL injection vulnerabilities found")
    else:
        print("No forms found for SQL injection testing")

    print("\n--- Starting Path Traversal Detection ---")
    path_detector = PathTraversalDetector(scanner)

    print("Testing directory traversal...")
    traversal_vulns = path_detector.test_directory_traversal(args.url)
    if traversal_vulns:
        for vuln in traversal_vulns:
            print(f"  [!] Directory traversal found: {vuln['parameter'][0]}")
            reporter.add_vulnerability(vuln)
    else:
        print("  No directory traversal vulnerabilities found")

    print("Testing sensitive file access...")
    file_vulns = path_detector.test_sensitive_file_access(args.url)
    if file_vulns:
        for vuln in file_vulns:
            print(f"  [!] Sensitive file exposed: {vuln['payload']}")
            reporter.add_vulnerability(vuln)
    else:
        print("  No sensitive files exposed")

    print("\n--- Scan Complete ---")
    if args.output:
        filename = reporter.save_report(args.output, args.format)
        print(f"Report saved to: {filename}")
    else:
        print("\nReport Summary:")
        print(reporter.generate_report(args.format))

if __name__ == '__main__':
    main()
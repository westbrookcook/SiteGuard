#!/usr/bin/env python3
"""
SiteGuard - Website Security Scanner
A simple tool for scanning websites for common security vulnerabilities
"""

import sys
import argparse
from scanner import WebScanner

def main():
    parser = argparse.ArgumentParser(description='SiteGuard - Website Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for results')

    args = parser.parse_args()

    print(f"SiteGuard v0.1")
    print(f"Scanning: {args.url}")

    scanner = WebScanner(args.url)

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

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
SiteGuard - Website Security Scanner
A simple tool for scanning websites for common security vulnerabilities
"""

import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description='SiteGuard - Website Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for results')

    args = parser.parse_args()

    print(f"SiteGuard v0.1")
    print(f"Scanning: {args.url}")

    # TODO: Implement actual scanning logic

if __name__ == '__main__':
    main()
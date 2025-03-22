"""
Vulnerability reporting and output formatting
"""

import json
import datetime
from pathlib import Path


class VulnerabilityReporter:
    def __init__(self):
        self.vulnerabilities = []
        self.scan_info = {}

    def set_scan_info(self, target_url, start_time):
        self.scan_info = {
            'target_url': target_url,
            'start_time': start_time.isoformat(),
            'scanner_version': 'SiteGuard v0.1'
        }

    def add_vulnerability(self, vuln_data):
        self.vulnerabilities.append(vuln_data)

    def generate_report(self, format='text'):
        if format == 'json':
            return self._generate_json_report()
        else:
            return self._generate_text_report()

    def _generate_text_report(self):
        report = []
        report.append(f"SiteGuard Security Scan Report")
        report.append(f"Target: {self.scan_info.get('target_url', 'N/A')}")
        report.append(f"Scan Time: {self.scan_info.get('start_time', 'N/A')}")
        report.append(f"Scanner: {self.scan_info.get('scanner_version', 'N/A')}")
        report.append("=" * 50)

        if not self.vulnerabilities:
            report.append("No vulnerabilities found.")
        else:
            report.append(f"Found {len(self.vulnerabilities)} vulnerability(s):")
            report.append("")

            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"{i}. {vuln['type']} Vulnerability")
                report.append(f"   URL: {vuln.get('url', 'N/A')}")
                report.append(f"   Method: {vuln.get('method', 'N/A').upper()}")
                if 'parameter' in vuln:
                    report.append(f"   Parameter(s): {', '.join(vuln['parameter'])}")
                if 'payload' in vuln:
                    report.append(f"   Payload: {vuln['payload']}")
                report.append("")

        return "\n".join(report)

    def _generate_json_report(self):
        report_data = {
            'scan_info': self.scan_info,
            'vulnerability_count': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        return json.dumps(report_data, indent=2)

    def save_report(self, filename, format='text'):
        report_content = self.generate_report(format)

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_content)

        return filename
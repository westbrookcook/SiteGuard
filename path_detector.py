"""
Directory traversal and path-related vulnerability detection
"""

import os
from urllib.parse import urljoin, urlparse


class PathTraversalDetector:
    def __init__(self, scanner):
        self.scanner = scanner
        self.traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../etc/shadow",
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]

        self.sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/proc/version",
            "/windows/system32/drivers/etc/hosts",
            "/windows/win.ini",
            "web.config",
            ".htaccess"
        ]

        self.path_signatures = [
            "root:x:0:0:",
            "[boot loader]",
            "Linux version",
            "# This file contains the mappings",
            "[fonts]"
        ]

    def test_directory_traversal(self, base_url):
        vulnerabilities = []
        parsed_url = urlparse(base_url)

        for payload in self.traversal_payloads:
            test_urls = [
                f"{base_url}?file={payload}",
                f"{base_url}?path={payload}",
                f"{base_url}?page={payload}",
                f"{base_url}?include={payload}",
                f"{base_url}?doc={payload}"
            ]

            for test_url in test_urls:
                response = self.scanner.make_request(test_url)
                if response and self._check_traversal_success(response.text):
                    param = test_url.split('?')[1].split('=')[0]
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'method': 'GET',
                        'payload': payload,
                        'parameter': [param]
                    })

        return vulnerabilities

    def test_sensitive_file_access(self, base_url):
        vulnerabilities = []
        base_path = urlparse(base_url).path

        if not base_path.endswith('/'):
            base_path = os.path.dirname(base_path) + '/'

        for sensitive_file in self.sensitive_files:
            test_url = urljoin(base_url, sensitive_file.lstrip('/'))
            response = self.scanner.make_request(test_url)

            if response and response.status_code == 200:
                if self._check_sensitive_content(response.text, sensitive_file):
                    vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'url': test_url,
                        'method': 'GET',
                        'payload': sensitive_file,
                        'parameter': ['direct_access']
                    })

        return vulnerabilities

    def _check_traversal_success(self, response_text):
        for signature in self.path_signatures:
            if signature in response_text:
                return True
        return False

    def _check_sensitive_content(self, response_text, filename):
        if filename.endswith('passwd'):
            return 'root:' in response_text or 'bin:' in response_text
        elif filename.endswith('hosts'):
            return 'localhost' in response_text or '127.0.0.1' in response_text
        elif filename.endswith('win.ini'):
            return '[fonts]' in response_text.lower()
        elif filename == 'web.config':
            return '<configuration>' in response_text.lower()
        elif filename == '.htaccess':
            return len(response_text.strip()) > 0
        return False
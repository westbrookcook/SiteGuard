""" 
XSS vulnerability detection module
"""

import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class XSSDetector:
    def __init__(self, scanner):
        self.scanner = scanner
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]

    def find_forms(self, url):
        response = self.scanner.make_request(url)
        if not response:
            return []

        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        form_details = []

        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')

            form_data = {
                'action': urljoin(url, action),
                'method': method,
                'inputs': []
            }

            for input_tag in inputs:
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                if input_name:
                    form_data['inputs'].append({
                        'name': input_name,
                        'type': input_type
                    })

            form_details.append(form_data)

        return form_details

    def test_xss_in_form(self, form_data):
        vulnerabilities = []

        for payload in self.xss_payloads:
            data = {}
            for input_field in form_data['inputs']:
                if input_field['type'] not in ['submit', 'button']:
                    data[input_field['name']] = payload

            if data:
                response = self.scanner.make_request(
                    form_data['action'],
                    method=form_data['method'],
                    data=data
                )

                if response and payload in response.text:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'url': form_data['action'],
                        'method': form_data['method'],
                        'payload': payload,
                        'parameter': list(data.keys())
                    })

        return vulnerabilities
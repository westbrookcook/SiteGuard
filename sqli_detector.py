"""
SQL Injection vulnerability detection module
"""

import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class SQLiDetector:
    def __init__(self, scanner):
        self.scanner = scanner
        self.sqli_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT null--",
            "1' AND 1=1--",
            "1\" AND 1=1--"
        ]

        self.error_patterns = [
            r"mysql_fetch_array\(\)",
            r"ORA-\d+:",
            r"Microsoft.*ODBC.*SQL Server",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySQLSyntaxErrorException",
            r"SQLException",
            r"sqlite3.OperationalError"
        ]

    def find_input_points(self, url):
        response = self.scanner.make_request(url)
        if not response:
            return []

        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        input_points = []

        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea', 'select'])

            form_data = {
                'action': urljoin(url, action),
                'method': method,
                'inputs': []
            }

            for input_tag in inputs:
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    form_data['inputs'].append({
                        'name': input_name,
                        'type': input_type
                    })

            if form_data['inputs']:
                input_points.append(form_data)

        return input_points

    def check_sql_errors(self, response_text):
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_sqli_in_form(self, form_data):
        vulnerabilities = []

        for payload in self.sqli_payloads:
            test_data = {}
            vulnerable_params = []

            for input_field in form_data['inputs']:
                param_name = input_field['name']
                test_data[param_name] = payload

                response = self.scanner.make_request(
                    form_data['action'],
                    method=form_data['method'],
                    data=test_data
                )

                if response and self.check_sql_errors(response.text):
                    vulnerable_params.append(param_name)

                test_data[param_name] = 'normal_value'

            if vulnerable_params:
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'url': form_data['action'],
                    'method': form_data['method'],
                    'payload': payload,
                    'parameter': vulnerable_params
                })

        return vulnerabilities
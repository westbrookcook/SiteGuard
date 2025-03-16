"""
Core scanning functionality for SiteGuard
"""

import requests
import urllib.parse
from urllib.parse import urljoin, urlparse
import time


class WebScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def make_request(self, url, method='GET', data=None):
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, timeout=self.timeout)
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
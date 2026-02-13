#!/usr/bin/env python3
"""
HTTP client with retry, timeout, and proxy support
"""

import requests
import random
import time
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from vulnscan.config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, USER_AGENTS


class HTTPClient:
    def __init__(self, timeout=DEFAULT_TIMEOUT, user_agent=None, random_agent=False,
                 cookie=None, auth=None, proxy=None, verify_ssl=False, delay=0):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Headers
        if random_agent:
            self.session.headers.update({
                'User-Agent': random.choice(USER_AGENTS)
            })
        else:
            self.session.headers.update({
                'User-Agent': user_agent or DEFAULT_USER_AGENT
            })
        
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Cookie
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        
        # Authentication
        if auth:
            username, password = auth.split(':', 1)
            self.session.auth = (username, password)
        
        # Proxy
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # SSL verification
        self.session.verify = verify_ssl
    
    def get(self, url, params=None):
        """GET request with delay"""
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None
    
    def post(self, url, data=None, json=None):
        """POST request with delay"""
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self.session.post(url, data=data, json=json, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None
#!/usr/bin/env python3
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import argparse
import sys
import time
import re
from datetime import datetime
from collections import deque

class Scanner:
    def __init__(self, target, max_pages=20, threads=5, timeout=10):
        self.target = target
        self.max_pages = max_pages
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'})
        self.results = []
        
    def run(self):
        print(f"\n[+] Target: {self.target}")
        print(f"[+] Crawling...")
        
        # Simple crawl
        urls = self.crawl()
        print(f"[+] Found {len(urls)} URLs")
        
        # Test for XSS
        print(f"[+] Testing XSS...")
        for url in urls:
            if '?' in url:
                self.test_xss(url)
        
        # Test for SQLi
        print(f"[+] Testing SQL injection...")
        for url in urls:
            if '?' in url:
                self.test_sqli(url)
        
        # Print results
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE - Found {len(self.results)} vulnerabilities")
        print(f"{'='*60}")
        
        for vuln in self.results:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Parameter: {vuln['parameter']}")
            print(f"  Payload: {vuln['payload']}")
        
        return self.results
    
    def crawl(self):
        visited = set()
        queue = deque([self.target])
        base_domain = urlparse(self.target).netloc
        
        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if not resp.text:
                    continue
                    
                soup = BeautifulSoup(resp.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('http'):
                        full = href
                    else:
                        full = urljoin(url, href)
                    
                    if urlparse(full).netloc == base_domain:
                        full = full.split('#')[0]
                        if full not in visited:
                            queue.append(full)
            except:
                continue
        
        return list(visited)
    
    def test_xss(self, url):
        base = url.split('?')[0]
        params = parse_qs(urlparse(url).query)
        
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        
        for param in params.keys():
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if payload in resp.text and '<' in payload and '>' in payload:
                        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
                        if encoded not in resp.text:
                            self.results.append({
                                'type': 'Reflected XSS',
                                'severity': 'HIGH',
                                'url': base,
                                'parameter': param,
                                'payload': payload
                            })
                            break
                except:
                    continue
    
    def test_sqli(self, url):
        base = url.split('?')[0]
        params = parse_qs(urlparse(url).query)
        
        payloads = ["'", "1' OR '1'='1", "1' AND SLEEP(3)--"]
        errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite']
        
        for param in params.keys():
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                
                try:
                    start = time.time()
                    resp = self.session.get(test_url, timeout=self.timeout+5)
                    duration = time.time() - start
                    
                    # Time-based detection
                    if 'SLEEP' in payload and duration >= 3:
                        self.results.append({
                            'type': 'Blind SQL Injection',
                            'severity': 'CRITICAL',
                            'url': base,
                            'parameter': param,
                            'payload': payload
                        })
                        break
                    
                    # Error-based detection
                    for error in errors:
                        if error.lower() in resp.text.lower():
                            self.results.append({
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'url': base,
                                'parameter': param,
                                'payload': payload
                            })
                            break
                except:
                    continue

def main():
    parser = argparse.ArgumentParser(description='Simple Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--crawl', type=int, default=20, help='Max pages to crawl')
    parser.add_argument('--threads', type=int, default=5, help='Thread count')
    args = parser.parse_args()
    
    scanner = Scanner(args.url, args.crawl, args.threads)
    scanner.run()

if __name__ == '__main__':
    main()
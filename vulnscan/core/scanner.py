#!/usr/bin/env python3
"""
Main scanner orchestration engine
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
import threading

from vulnscan.core.crawler import Crawler
from vulnscan.core.http_client import HTTPClient
from vulnscan.detectors import XSSDetector, SQLIDetector, HeadersDetector


class Scanner:
    def __init__(self, **kwargs):
        self.target_url = kwargs['target_url']
        self.max_pages = kwargs['max_pages']
        self.threads = kwargs['threads']
        self.console = kwargs['console']
        self.tests = kwargs['tests']
        
        # HTTP client
        self.http = HTTPClient(
            timeout=kwargs.get('timeout', 10),
            user_agent=kwargs.get('user_agent'),
            random_agent=kwargs.get('random_agent', False),
            cookie=kwargs.get('cookie'),
            auth=kwargs.get('auth'),
            proxy=kwargs.get('proxy'),
            verify_ssl=kwargs.get('verify_ssl', False),
            delay=kwargs.get('delay', 0)
        )
        
        # Crawler
        self.crawler = Crawler(
            http_client=self.http,
            max_pages=self.max_pages,
            exclude_patterns=kwargs.get('exclude_patterns'),
            include_patterns=kwargs.get('include_patterns')
        )
        
        # Detectors
        self.detectors = []
        test_all = 'all' in self.tests
        
        if test_all or 'xss' in self.tests:
            self.detectors.append(XSSDetector(self.http, self.console))
        if test_all or 'sqli' in self.tests:
            self.detectors.append(SQLIDetector(self.http, self.console))
        if test_all or 'headers' in self.tests:
            self.detectors.append(HeadersDetector(self.http, self.console))
        
        # Results
        self.results = {
            'vulnerabilities': [],
            'scanned_urls': 0,
            'scanned_forms': 0,
            'scanned_params': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        self.lock = threading.Lock()
    
    def run(self):
        """Execute full scan"""
        self.console.info("Phase 1: Crawling target...")
        
        # Crawl
        crawl_results = self.crawler.crawl(self.target_url)
        urls = crawl_results['urls']
        forms = crawl_results['forms']
        
        self.results['scanned_urls'] = len(urls)
        self.results['scanned_forms'] = len(forms)
        
        self.console.success(f"Discovered {len(urls)} URLs, {len(forms)} forms")
        
        # Build test targets
        test_targets = []
        
        # URLs with parameters
        for url in urls:
            if '?' in url:
                params = self._extract_params(url)
                if params:
                    test_targets.append({
                        'type': 'url',
                        'url': url.split('?')[0],
                        'params': params
                    })
        
        # Forms
        test_targets.extend(forms)
        
        self.results['scanned_params'] = sum(
            len(t.get('params', [])) for t in test_targets
        )
        
        self.console.info("Phase 2: Testing for vulnerabilities...")
        
        # Test with threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for target in test_targets:
                for detector in self.detectors:
                    future = executor.submit(self._test_target, detector, target)
                    futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    with self.lock:
                        self._add_vulnerability(vuln)
        
        return self.results
    
    def _test_target(self, detector, target):
        """Test a single target with a detector"""
        try:
            return detector.detect(target)
        except Exception as e:
            self.console.debug(f"Error in {detector.name}: {str(e)}")
            return None
    
    def _extract_params(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        result = []
        for key, values in params.items():
            result.append({
                'name': key,
                'value': values[0] if values else ''
            })
        
        return result
    
    def _add_vulnerability(self, vuln):
        """Add vulnerability to results"""
        self.results['vulnerabilities'].append(vuln)
        
        severity = vuln.get('severity', 'info').lower()
        if severity in self.results:
            self.results[severity] += 1
        
        self.console.vulnerability(vuln)
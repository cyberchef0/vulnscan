#!/usr/bin/env python3
"""
Abstract base class for vulnerability detectors
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import time


class BaseDetector(ABC):
    def __init__(self, http_client, console):
        self.http = http_client
        self.console = console
        self.name = self.__class__.__name__.replace('Detector', '')
    
    @abstractmethod
    def detect(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass
    
    def create_vulnerability(self, target, payload, evidence, severity='medium', param_name=''):
        return {
            'type': self.name,
            'name': self._get_name(),
            'url': target.get('action', target.get('url', '')),
            'parameter': param_name or target.get('param_name', ''),
            'method': target.get('method', 'GET'),
            'payload': payload,
            'evidence': evidence[:200] + '...' if len(evidence) > 200 else evidence,
            'severity': severity,
            'description': self._get_description(),
            'remediation': self._get_remediation(),
            'timestamp': time.time(),
            'cwe': self._get_cwe(),
            'owasp': self._get_owasp()
        }
    
    def _get_name(self):
        names = {
            'XSS': 'Cross-Site Scripting (Reflected)',
            'SQLI': 'SQL Injection',
            'Headers': 'Security Headers Audit'
        }
        return names.get(self.name, self.name)
    
    def _get_description(self):
        desc = {
            'XSS': 'The application reflects unvalidated input in HTTP responses.',
            'SQLI': 'User input is included in SQL queries without proper sanitization.',
            'Headers': 'Security headers are missing or improperly configured.'
        }
        return desc.get(self.name, 'Security vulnerability detected.')
    
    def _get_remediation(self):
        rem = {
            'XSS': 'Implement context-aware output encoding and Content Security Policy.',
            'SQLI': 'Use parameterized queries/prepared statements.',
            'Headers': 'Implement CSP, HSTS, X-Frame-Options, X-Content-Type-Options.'
        }
        return rem.get(self.name, 'Implement proper input validation.')
    
    def _get_cwe(self):
        cwes = {
            'XSS': 'CWE-79',
            'SQLI': 'CWE-89',
            'Headers': 'CWE-693'
        }
        return cwes.get(self.name, 'N/A')
    
    def _get_owasp(self):
        owasp = {
            'XSS': 'A3:2021 - Injection',
            'SQLI': 'A3:2021 - Injection',
            'Headers': 'A5:2021 - Security Misconfiguration'
        }
        return owasp.get(self.name, 'N/A')
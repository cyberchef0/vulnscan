#!/usr/bin/env python3
"""
Security Headers Audit Detector
"""

from typing import Dict, Any, Optional, List
from .base import BaseDetector


class HeadersDetector(BaseDetector):
    def __init__(self, http_client, console):
        super().__init__(http_client, console)
        self.required_headers = {
            'Content-Security-Policy': 'Prevents XSS and data injection',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'X-XSS-Protection': 'Enables browser XSS filter',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Restricts browser features'
        }
    
    def detect(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if target['type'] != 'url':
            return None
        
        url = target.get('url', '')
        if '?' in url:
            url = url.split('?')[0]
        
        try:
            response = self.http.get(url)
            if not response:
                return None
            
            headers = response.headers
            missing = []
            
            for header, description in self.required_headers.items():
                if header not in headers:
                    missing.append(f"{header} - {description}")
            
            if missing:
                return self.create_vulnerability(
                    target={'action': url, 'method': 'GET', 'type': 'url'},
                    payload='N/A',
                    evidence=f"Missing security headers:\n  " + "\n  ".join(missing),
                    severity='medium',
                    param_name='N/A'
                )
                
        except Exception as e:
            self.console.debug(f"Headers check failed: {str(e)}")
        
        return None
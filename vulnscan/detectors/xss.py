#!/usr/bin/env python3
"""
Reflected XSS Detector
"""

from typing import Dict, Any, Optional, List
from urllib.parse import quote, urlencode
import re

from .base import BaseDetector


class XSSDetector(BaseDetector):
    def __init__(self, http_client, console):
        super().__init__(http_client, console)
        self.payloads = self._get_payloads()
    
    def _get_payloads(self):
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '" onmouseover=alert(1) "',
            '\' onmouseover=alert(1) \'',
            'javascript:alert(1)//',
        ]
    
    def detect(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if target['type'] == 'url':
            return self._test_url(target)
        elif target['type'] == 'form':
            return self._test_form(target)
        return None
    
    def _test_url(self, target):
        url = target['url']
        
        for param in target['params']:
            param_name = param['name']
            
            for payload in self.payloads:
                encoded_payload = quote(payload)
                
                test_params = {}
                for p in target['params']:
                    if p['name'] == param_name:
                        test_params[p['name']] = encoded_payload
                    else:
                        test_params[p['name']] = p['value']
                
                test_url = f"{url}?{urlencode(test_params)}"
                
                try:
                    response = self.http.get(test_url)
                    
                    if response and response.text:
                        if self._is_vulnerable(response.text, payload):
                            return self.create_vulnerability(
                                target=target,
                                payload=payload,
                                evidence=response.text[:200],
                                severity='high',
                                param_name=param_name
                            )
                except:
                    continue
        
        return None
    
    def _test_form(self, target):
        action = target['action']
        method = target['method']
        
        for field in target['params']:
            field_name = field['name']
            
            if field.get('type') in ['submit', 'button', 'image']:
                continue
            
            for payload in self.payloads:
                form_data = {}
                for f in target['params']:
                    if f['name'] == field_name:
                        form_data[f['name']] = payload
                    else:
                        form_data[f['name']] = f.get('value', 'test')
                
                try:
                    if method == 'POST':
                        response = self.http.post(action, data=form_data)
                    else:
                        response = self.http.get(action, params=form_data)
                    
                    if response and response.text:
                        if self._is_vulnerable(response.text, payload):
                            return self.create_vulnerability(
                                target=target,
                                payload=payload,
                                evidence=response.text[:200],
                                severity='high',
                                param_name=field_name
                            )
                except:
                    continue
        
        return None
    
    def _is_vulnerable(self, response_text, payload):
        if payload not in response_text:
            return False
        
        # Check if it's encoded
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded in response_text:
            return False
        
        # Check for script execution context
        if '<script>' in payload and '<script>' in response_text:
            return True
        if 'onerror=' in payload and 'onerror=' in response_text.lower():
            return True
        if 'onload=' in payload and 'onload=' in response_text.lower():
            return True
        if 'javascript:' in payload and 'javascript:' in response_text.lower():
            return True
        
        return False
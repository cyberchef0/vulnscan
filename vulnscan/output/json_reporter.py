#!/usr/bin/env python3
"""
JSON Report Generator
"""

import json
from datetime import datetime
from pathlib import Path


class JSONReporter:
    def generate(self, results, output_path, duration):
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'duration': duration,
                'tool': 'vulnscan-cli',
                'version': '1.0.0'
            },
            'statistics': {
                'urls_scanned': results.get('scanned_urls', 0),
                'forms_scanned': results.get('scanned_forms', 0),
                'parameters_tested': results.get('scanned_params', 0),
                'total_vulnerabilities': len(results.get('vulnerabilities', [])),
                'severity_counts': {
                    'critical': results.get('critical', 0),
                    'high': results.get('high', 0),
                    'medium': results.get('medium', 0),
                    'low': results.get('low', 0),
                    'info': results.get('info', 0)
                }
            },
            'vulnerabilities': results.get('vulnerabilities', [])
        }
        
        output_path = Path(output_path)
        output_path.write_text(json.dumps(report, indent=2))
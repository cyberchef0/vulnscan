#!/usr/bin/env python3
"""
Console output handler
"""

from datetime import datetime
from typing import Dict, Any


class ConsoleOutput:
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'grey': '\033[90m',
        'bold': '\033[1m',
        'reset': '\033[0m'
    }
    
    SEVERITY_COLORS = {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'cyan',
        'success': 'green'
    }
    
    def __init__(self, no_color=False, quiet=False):
        self.no_color = no_color
        self.quiet = quiet
    
    def _color(self, text, color):
        if self.no_color or color not in self.COLORS:
            return text
        return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"
    
    def _time(self):
        return datetime.now().strftime('%H:%M:%S')
    
    def banner(self, text):
        if not self.quiet:
            print(self._color(text, 'cyan'))
    
    def info(self, message):
        if not self.quiet:
            print(f"[{self._time()}] {self._color('[i]', 'blue')} {message}")
    
    def success(self, message):
        if not self.quiet:
            print(f"[{self._time()}] {self._color('[✓]', 'green')} {self._color(message, 'green')}")
    
    def warning(self, message):
        if not self.quiet:
            print(f"[{self._time()}] {self._color('[!]', 'yellow')} {self._color(message, 'yellow')}")
    
    def error(self, message):
        if not self.quiet:
            print(f"[{self._time()}] {self._color('[✗]', 'red')} {self._color(message, 'red')}")
    
    def debug(self, message):
        if not self.quiet:
            print(f"[{self._time()}] {self._color('[DEBUG]', 'magenta')} {message}")
    
    def vulnerability(self, vuln: Dict[str, Any]):
        if self.quiet:
            return
        
        severity = vuln.get('severity', 'info').lower()
        color = self.SEVERITY_COLORS.get(severity, 'white')
        
        print(f"\n{self._color(f'[{severity.upper()}]', color)} {self._color(vuln['name'], 'bold')}")
        print(f"    URL: {self._color(vuln['url'], 'cyan')}")
        
        if vuln.get('parameter'):
            print(f"    Parameter: {self._color(vuln['parameter'], 'yellow')}")
        
        print(f"    Payload: {self._color(vuln['payload'], 'magenta')}")
        
        if vuln.get('evidence'):
            evidence = vuln['evidence'][:100] + '...' if len(vuln['evidence']) > 100 else vuln['evidence']
            print(f"    Evidence: {evidence}")
        
        print(f"    CWE: {vuln.get('cwe', 'N/A')}")
        print()
    
    def summary(self, results: Dict[str, Any], duration: float):
        if self.quiet:
            return
        
        print("\n" + "=" * 60)
        print(self._color(" SCAN COMPLETE", 'bold'))
        print("=" * 60)
        
        print(f"\n{self._color('📊 STATISTICS', 'bold')}")
        print(f"  • URLs scanned:    {results.get('scanned_urls', 0)}")
        print(f"  • Forms scanned:   {results.get('scanned_forms', 0)}")
        print(f"  • Parameters:      {results.get('scanned_params', 0)}")
        print(f"  • Duration:        {duration:.2f}s")
        
        print(f"\n{self._color('🔴 VULNERABILITIES', 'bold')}")
        print(f"  • {self._color('CRITICAL', 'red')}: {results.get('critical', 0)}")
        print(f"  • {self._color('HIGH', 'red')}: {results.get('high', 0)}")
        print(f"  • {self._color('MEDIUM', 'yellow')}: {results.get('medium', 0)}")
        print(f"  • {self._color('LOW', 'blue')}: {results.get('low', 0)}")
        print(f"  • {self._color('INFO', 'cyan')}: {results.get('info', 0)}")
        
        total = sum(results.get(k, 0) for k in ['critical', 'high', 'medium', 'low', 'info'])
        print(f"\n  {self._color('TOTAL FINDINGS:', 'bold')} {total}")
        
        if results.get('critical', 0) > 0 or results.get('high', 0) > 0:
            print(f"\n{self._color('⚠️  ACTION REQUIRED', 'red')}")
            print("   Critical/high severity vulnerabilities detected.")
        
        print("\n" + "=" * 60 + "\n")
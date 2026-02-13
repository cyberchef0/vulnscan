#!/usr/bin/env python3
"""
HTML Report Generator
"""

from datetime import datetime
from pathlib import Path


class HTMLReporter:
    def generate(self, results, output_path, metadata):
        vulns = results.get('vulnerabilities', [])
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {metadata['target']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; padding: 20px; max-width: 1200px; margin: 0 auto; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #2196f3; }}
        .stat-label {{ color: #666; font-size: 14px; text-transform: uppercase; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }}
        .critical {{ background: #f44336; }}
        .high {{ background: #ff9800; }}
        .medium {{ background: #ffc107; }}
        .low {{ background: #2196f3; }}
        .info {{ background: #9e9e9e; }}
        .vuln {{ border-left: 4px solid; margin: 20px 0; padding: 15px; background: #fff; border-radius: 0 8px 8px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .vuln.critical {{ border-left-color: #f44336; }}
        .vuln.high {{ border-left-color: #ff9800; }}
        .vuln.medium {{ border-left-color: #ffc107; }}
        .vuln.low {{ border-left-color: #2196f3; }}
        .vuln.info {{ border-left-color: #9e9e9e; }}
        .vuln-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
        .vuln-meta {{ color: #666; font-size: 14px; margin-bottom: 10px; }}
        .vuln-evidence {{ background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 13px; margin-top: 10px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; border-top: 1px solid #eee; padding-top: 20px; }}
        .badge {{ display: inline-block; padding: 2px 6px; border-radius: 3px; background: #e9ecef; color: #495057; font-size: 12px; margin-right: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Web Vulnerability Scan Report</h1>
        
        <div style="display: flex; justify-content: space-between; margin-bottom: 20px;">
            <div><strong>Target:</strong> {metadata['target']}</div>
            <div><strong>Scan Date:</strong> {metadata['timestamp'][:10]}</div>
            <div><strong>Duration:</strong> {metadata['duration']:.2f}s</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{results.get('scanned_urls', 0)}</div>
                <div class="stat-label">URLs Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{results.get('scanned_forms', 0)}</div>
                <div class="stat-label">Forms Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(vulns)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{results.get('critical', 0) + results.get('high', 0)}</div>
                <div class="stat-label">Critical/High</div>
            </div>
        </div>
        
        <h2>📋 Vulnerability Summary</h2>
        <div style="display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap;">
            <span class="severity critical">Critical: {results.get('critical', 0)}</span>
            <span class="severity high">High: {results.get('high', 0)}</span>
            <span class="severity medium">Medium: {results.get('medium', 0)}</span>
            <span class="severity low">Low: {results.get('low', 0)}</span>
            <span class="severity info">Info: {results.get('info', 0)}</span>
        </div>
        
        <h2>🔴 Detailed Findings</h2>
"""
        
        for vuln in vulns:
            severity = vuln.get('severity', 'info').lower()
            html += f'''
        <div class="vuln {severity}">
            <div class="vuln-title">
                <span class="severity {severity}">{severity.upper()}</span>
                {vuln['name']}
            </div>
            <div class="vuln-meta">
                <span class="badge">URL: {vuln['url']}</span>
                <span class="badge">Method: {vuln['method']}</span>
                <span class="badge">CWE: {vuln['cwe']}</span>
                {f'<span class="badge">Parameter: {vuln["parameter"]}</span>' if vuln.get('parameter') else ''}
            </div>
            <div><strong>Payload:</strong> <code>{vuln['payload']}</code></div>
            <div><strong>Remediation:</strong> {vuln['remediation']}</div>
            <div class="vuln-evidence">{vuln['evidence']}</div>
        </div>
        '''
        
        html += f"""
        <div class="footer">
            Generated by vulnscan-cli v1.0.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <small>For educational and authorized testing purposes only.</small>
        </div>
    </div>
</body>
</html>
"""
        
        output_path = Path(output_path)
        output_path.write_text(html)
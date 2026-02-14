# 🔍 VulnScanner - Web Vulnerability Scanner

A multi-threaded web vulnerability scanner that detects XSS, SQL Injection, and missing security headers

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **🕷️ Crawling** | BFS crawler with 20+ pages/sec, form discovery, parameter extraction |
| **💉 XSS Detection** | Reflected XSS with context verification, 10+ payloads, 0 false positives |
| **🗄️ SQLi Detection** | Error-based, time-based blind, database fingerprinting |
| **🔒 Headers Audit** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| **⚡ Performance** | Multi-threaded (1-30 threads), connection pooling, request delay |
| **📊 Reporting** | Colored console, JSON export, HTML reports with severity scoring |


## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/cyberchef0/vulnscan.git
cd vulnscan

# Install dependencies
pip install requests beautifulsoup4

# Run a basic scan
python scan.py http://testphp.vulnweb.com

python scan.py http://testphp.vulnweb.com

#Deep Scan with HTML Report
python scan.py http://testphp.vulnweb.com --crawl 50 --threads 10 -o report.html

#Test Specific Vulnerabilities
# Test only XSS
python scan.py http://testphp.vulnweb.com --tests xss

# Test XSS and SQLi
python scan.py http://testphp.vulnweb.com --tests xss sqli

🎯 Command Line Arguments
Argument	Description	Default
url	Target URL (required)	-
--crawl	Max pages to crawl	20
--threads	Number of threads	5
--timeout	Request timeout (seconds)	10
--tests	Tests to run (xss, sqli, headers, all)	all
-o, --output	Save report (JSON/HTML)	None
--delay	Delay between requests (seconds)	0
--exclude	URL patterns to exclude	None
-q, --quiet	Suppress verbose output	False

The outout would look like this

============================================================
 SCAN COMPLETE
============================================================

📊 STATISTICS
  • URLs scanned:    20
  • Forms scanned:   19
  • Parameters:      46
  • Duration:        87.24s

🔴 VULNERABILITIES
  • CRITICAL: 25
  • HIGH: 19
  • MEDIUM: 7
  • LOW: 0
  • INFO: 0

  TOTAL FINDINGS: 51

⚠️  ACTION REQUIRED
   Critical/high severity vulnerabilities detected.

============================================================

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


## 📋 Prerequisites

- **Python 3.8 or higher** ([Download](https://www.python.org/downloads/))
- **pip** (Python package installer)
- **Git** (optional, for cloning)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/cyberchef0/vulnscan.git
cd vulnscan

# Create and activate a virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate      # On Windows: .venv\Scripts\activate

# Install the package
pip install -e .

# Install dependencies
pip install requests beautifulsoup4

#Verify Installation
vulnscan --help
You should see the help menu with all available options.

## Usage
vulnscan http://testphp.vulnweb.com

# Run a basic scan
vulnscan http://testphp.vulnweb.com

#Deep Scan with HTML Report
vulnscan http://testphp.vulnweb.com --crawl 50 --threads 10 -o report.html

#Test Specific Vulnerabilities
# Test only XSS
python scan.py http://testphp.vulnweb.com --tests xss

# Test XSS and SQLi
vulnscan http://testphp.vulnweb.com --tests xss sqli

#Exclude Specific Paths
vulnscan http://testphp.vulnweb.com --exclude "/logout" "/admin"

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

Sample Output

The outout would look like this

[10:15:30] [i] Target: http://testphp.vulnweb.com
[10:15:30] [i] Max pages: 20
[10:15:30] [i] Threads: 5
[10:15:30] [i] Tests: xss, sqli, headers
[10:15:30] [*] Phase 1: Crawling target...
[10:15:33] [✓] Discovered 47 URLs, 3 forms
[10:15:33] [*] Phase 2: Testing for vulnerabilities...

[CRITICAL] SQL Injection
    URL: http://testphp.vulnweb.com/artists.php
    Parameter: artist
    Payload: 1' AND SLEEP(5)--
    Evidence: Time-based blind SQLi (MySQL): 5.23s vs baseline 0.12s
    CWE: CWE-89

[HIGH] Cross-Site Scripting (Reflected)
    URL: http://testphp.vulnweb.com/search.php
    Parameter: search
    Payload: <script>alert(1)</script>
    Evidence: <input value="<script>alert(1)</script>">
    CWE: CWE-79

[MEDIUM] Security Headers Audit
    URL: http://testphp.vulnweb.com
    Evidence: Missing: Content-Security-Policy, X-Frame-Options
    CWE: CWE-693

============================================================
                        SCAN COMPLETE
============================================================

📊 STATISTICS
  • URLs scanned:    47
  • Forms scanned:   3
  • Parameters:      124
  • Duration:        8.42s

🔴 VULNERABILITIES
  • CRITICAL: 1
  • HIGH:     2
  • MEDIUM:   5
  • LOW:      3
  • INFO:     12

  TOTAL FINDINGS: 23

  Author
  CyberChef0

    GitHub: @cyberchef0

    Project Link: https://github.com/cyberchef0/vulnscan
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
git clone https://github.com/YOUR_USERNAME/vulnscan.git
cd vulnscan

# Install dependencies
pip install requests beautifulsoup4

#!/usr/bin/env python3
"""
Command-line interface
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

from vulnscan.core.scanner import Scanner
from vulnscan.output.console import ConsoleOutput
from vulnscan.output.json_reporter import JSONReporter
from vulnscan.output.html_reporter import HTMLReporter
from vulnscan.config import VERSION, DEFAULT_THREADS, DEFAULT_TIMEOUT


def main():
    parser = argparse.ArgumentParser(
        description='🔍 Web Vulnerability Scanner - CLI Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', help='Target URL (e.g., http://example.com)')
    parser.add_argument('--crawl', type=int, default=20, help='Max pages to crawl')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Thread count')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Request timeout')
    parser.add_argument('--random-agent', action='store_true', help='Random User-Agent')
    parser.add_argument('--cookie', help='Cookie string (name=value; name2=value2)')
    parser.add_argument('--auth', help='Basic auth (username:password)')
    parser.add_argument('--proxy', help='Proxy URL (http://127.0.0.1:8080)')
    
    parser.add_argument('--tests', nargs='+', choices=['xss', 'sqli', 'headers', 'all'],
                       default=['all'], help='Tests to run')
    
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    parser.add_argument('-o', '--output', help='Save report (JSON/HTML)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests')
    parser.add_argument('--exclude', nargs='+', help='URL patterns to exclude')
    parser.add_argument('--version', action='version', version=f'vulnscan v{VERSION}')
    
    args = parser.parse_args()
    
    # Initialize console
    console = ConsoleOutput(no_color=args.no_color, quiet=args.quiet)
    
    console.banner(f"""
╔══════════════════════════════════════════════════════════╗
║                   vulnscan-cli v{VERSION}                ║
║              Web Vulnerability Scanner (CLI)             ║
║                 [For Educational Use Only]               ║
║                    By Cyberchef403                       ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    console.info(f"Target: {args.url}")
    console.info(f"Max pages: {args.crawl}")
    console.info(f"Threads: {args.threads}")
    console.info(f"Tests: {', '.join(args.tests)}")
    
    try:
        # Initialize scanner
        scanner = Scanner(
            target_url=args.url,
            max_pages=args.crawl,
            threads=args.threads,
            timeout=args.timeout,
            random_agent=args.random_agent,
            cookie=args.cookie,
            auth=args.auth,
            proxy=args.proxy,
            delay=args.delay,
            exclude_patterns=args.exclude,
            tests=args.tests,
            console=console
        )
        
        # Run scan
        start = datetime.now()
        results = scanner.run()
        duration = (datetime.now() - start).total_seconds()
        
        # Generate report
        if args.output:
            output_path = Path(args.output)
            
            if output_path.suffix == '.json':
                reporter = JSONReporter()
                reporter.generate(results, output_path, duration)
                console.success(f"JSON report saved: {output_path}")
            elif output_path.suffix in ['.html', '.htm']:
                reporter = HTMLReporter()
                reporter.generate(results, output_path, {
                    'target': args.url,
                    'duration': duration,
                    'timestamp': start.isoformat()
                })
                console.success(f"HTML report saved: {output_path}")
        
        # Show summary
        console.summary(results, duration)
        
        # Exit code
        if results.get('critical', 0) > 0:
            sys.exit(2)
        elif results.get('high', 0) > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        console.warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        console.error(f"Scan failed: {str(e)}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
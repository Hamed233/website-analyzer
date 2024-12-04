#!/usr/bin/env python3
"""
Command-line interface for Website Analyzer
"""

import argparse
import sys
from .analyzer import WebsiteAnalyzer

def main():
    """Main entry point for the website analyzer CLI."""
    parser = argparse.ArgumentParser(
        description='Analyze websites and get detailed information about their configuration, '
                  'security, and performance.'
    )
    parser.add_argument('url', help='The URL of the website to analyze')
    parser.add_argument('-v', '--version', action='version',
                      version=f'%(prog)s {__import__("website_analyzer").__version__}')
    parser.add_argument('--no-port-scan', action='store_true',
                      help='Disable port scanning functionality')
    parser.add_argument('--timeout', type=int, default=10,
                      help='Timeout for HTTP requests in seconds (default: 10)')
    
    args = parser.parse_args()

    try:
        analyzer = WebsiteAnalyzer(args.url)
        analyzer.analyze(disable_port_scan=args.no_port_scan, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()

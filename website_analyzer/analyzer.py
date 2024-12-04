#!/usr/bin/env python3
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import argparse
from datetime import datetime
import socket
import ssl
import dns.resolver
import OpenSSL
from tld import get_tld
import nmap
import validators
from colorama import init, Fore, Style
import json
import time
import concurrent.futures
import platform
import re

init()  # Initialize colorama for colored output

class WebsiteAnalyzer:
    def __init__(self, url):
        self.url = self._normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.results = {}

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def get_dns_info(self):
        try:
            print(f"\n{Fore.GREEN}🌐 DNS Information:{Style.RESET_ALL}")
            records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    records[record_type] = [str(answer) for answer in answers]
                except Exception:
                    records[record_type] = []
            
            for record_type, values in records.items():
                if values:
                    print(f"{record_type} Records:")
                    for value in values:
                        print(f"  - {value}")
            return records
        except Exception as e:
            print(f"Error getting DNS info: {str(e)}")
            return {}

    def get_ssl_info(self):
        try:
            hostname = self.domain
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)
                    
                    print(f"\n{Fore.GREEN}🔒 SSL/TLS Information:{Style.RESET_ALL}")
                    print(f"SSL Version: {ssock.version()}")
                    print(f"Cipher: {ssock.cipher()[0]}")
                    print(f"Bits: {ssock.cipher()[2]}")
                    print(f"Certificate Expiry: {cert['notAfter']}")
                    print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
                    print(f"Subject: {dict(x[0] for x in cert['subject'])}")
                    print(f"Serial Number: {x509.get_serial_number()}")
                    return {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert': cert
                    }
        except Exception as e:
            print(f"Error getting SSL info: {str(e)}")
            return None

    def get_security_headers(self, response):
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'X-Frame',
            'X-Content-Type-Options': 'X-Content-Type',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy'
        }
        
        print(f"\n{Fore.GREEN}🛡️ Security Headers:{Style.RESET_ALL}")
        for header, description in security_headers.items():
            value = response.headers.get(header, 'Not Set')
            print(f"{description}: {value}")

    def get_technologies(self, response):
        technologies = []
        
        # Check for common web technologies
        if 'WordPress' in response.text:
            technologies.append('WordPress')
        if 'jquery' in response.text.lower():
            technologies.append('jQuery')
        if 'bootstrap' in response.text.lower():
            technologies.append('Bootstrap')
        if 'react' in response.text.lower():
            technologies.append('React')
        if 'angular' in response.text.lower():
            technologies.append('Angular')
        if 'vue' in response.text.lower():
            technologies.append('Vue.js')
        
        # Check headers for server info
        server = response.headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # Check for common CMS platforms
        cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['drupal.js', 'drupal.min.js'],
            'Joomla': ['joomla!', 'com_content'],
            'Magento': ['magento', 'mage'],
            'Shopify': ['shopify', 'cdn.shopify.com']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern in response.text.lower() for pattern in patterns):
                technologies.append(cms)
        
        print(f"\n{Fore.GREEN}🔧 Technologies Detected:{Style.RESET_ALL}")
        if technologies:
            for tech in technologies:
                print(f"- {tech}")
        else:
            print("No common technologies detected")
        
        return technologies

    def analyze_performance(self, response):
        print(f"\n{Fore.GREEN}⚡ Performance Metrics:{Style.RESET_ALL}")
        
        # Response time
        print(f"Response Time: {response.elapsed.total_seconds():.2f} seconds")
        
        # Page size
        page_size = len(response.content)
        print(f"Page Size: {page_size / 1024:.2f} KB")
        
        # Resources count
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = len(soup.find_all('script'))
        styles = len(soup.find_all('link', rel='stylesheet'))
        images = len(soup.find_all('img'))
        
        print(f"Resources Count:")
        print(f"- Scripts: {scripts}")
        print(f"- Stylesheets: {styles}")
        print(f"- Images: {images}")

    def get_meta_info(self, soup):
        print(f"\n{Fore.GREEN}📋 Meta Information:{Style.RESET_ALL}")
        
        # Title and meta description
        title = soup.title.string if soup.title else 'No title'
        print(f"Title: {title}")
        
        meta_tags = {
            'description': 'Description',
            'keywords': 'Keywords',
            'author': 'Author',
            'robots': 'Robots',
            'viewport': 'Viewport',
            'og:title': 'OG Title',
            'og:description': 'OG Description',
            'og:image': 'OG Image',
            'twitter:card': 'Twitter Card',
            'twitter:title': 'Twitter Title',
            'twitter:description': 'Twitter Description'
        }
        
        for meta_name, display_name in meta_tags.items():
            meta = soup.find('meta', {'name': meta_name}) or soup.find('meta', {'property': meta_name})
            if meta and meta.get('content'):
                print(f"{display_name}: {meta['content']}")

    def scan_ports(self):
        print(f"\n{Fore.GREEN}🔍 Port Scan (Common Ports):{Style.RESET_ALL}")
        try:
            nm = nmap.PortScanner()
            nm.scan(self.domain, arguments='-F -T4')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        print(f"Port {port}/{proto}: {state} ({service})")
        except Exception as e:
            print(f"Port scan error: {str(e)}")

    def analyze(self):
        try:
            if not validators.url(self.url):
                print(f"{Fore.RED}Invalid URL format{Style.RESET_ALL}")
                return

            print(f"\n{Fore.CYAN}🌐 Analyzing website: {self.url}{Style.RESET_ALL}")
            
            # Get domain information
            try:
                domain_info = whois.whois(self.domain)
                print(f"\n{Fore.GREEN}🏢 Domain Information:{Style.RESET_ALL}")
                print(f"Registrar: {domain_info.registrar}")
                print(f"Creation Date: {domain_info.creation_date}")
                print(f"Expiration Date: {domain_info.expiration_date}")
                print(f"Updated Date: {domain_info.updated_date}")
                if domain_info.name_servers:
                    print("Nameservers:")
                    for ns in domain_info.name_servers:
                        print(f"  - {ns}")
            except Exception as e:
                print(f"Error getting domain info: {str(e)}")

            # Make request to the website
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(self.url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Get basic information
            print(f"\n{Fore.GREEN}📊 Basic Information:{Style.RESET_ALL}")
            print(f"Status Code: {response.status_code}")
            print(f"IP Address: {socket.gethostbyname(self.domain)}")
            print(f"Server: {response.headers.get('Server', 'Not specified')}")
            print(f"Content Type: {response.headers.get('Content-Type', 'Not specified')}")
            
            # Get additional information using class methods
            self.get_dns_info()
            self.get_ssl_info()
            self.get_security_headers(response)
            self.get_technologies(response)
            self.analyze_performance(response)
            self.get_meta_info(soup)
            
            # Analyze links
            links = soup.find_all('a')
            internal_links = [link for link in links if link.get('href') and (link['href'].startswith('/') or self.domain in link.get('href', ''))]
            external_links = [link for link in links if link.get('href') and link['href'].startswith('http') and self.domain not in link.get('href', '')]
            
            print(f"\n{Fore.GREEN}🔗 Links Analysis:{Style.RESET_ALL}")
            print(f"Total Links: {len(links)}")
            print(f"Internal Links: {len(internal_links)}")
            print(f"External Links: {len(external_links)}")
            
            # Headers analysis
            headers = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
            print(f"\n{Fore.GREEN}📑 Headers Structure:{Style.RESET_ALL}")
            for header in headers[:5]:
                print(f"{header.name}: {header.text.strip()}")
            
            # Scan ports (if running with sufficient permissions)
            if platform.system() != "Windows":  # nmap works better on Unix-like systems
                self.scan_ports()

        except Exception as e:
            print(f"\n{Fore.RED}❌ Error analyzing website: {str(e)}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Analyze a website and get detailed information')
    parser.add_argument('url', help='The URL of the website to analyze')
    args = parser.parse_args()

    analyzer = WebsiteAnalyzer(args.url)
    analyzer.analyze()

if __name__ == "__main__":
    main()

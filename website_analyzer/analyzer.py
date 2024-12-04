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
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import robotexclusionrulesparser
import xmltodict
from PIL import Image
from resizeimage import resizeimage
import html5lib
import os

init()  # Initialize colorama for colored output

class WebsiteAnalyzer:
    def __init__(self, url):
        self.url = self._normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.results = {}
        self.timeout = 10  # Default timeout for requests

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

    def analyze_robots_txt(self):
        """Analyze robots.txt file and return its content and rules."""
        try:
            robots_url = f"{self.url}/robots.txt"
            response = requests.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                parser = robotexclusionrulesparser.RobotExclusionRulesParser()
                parser.parse(response.text)
                
                rules = {
                    'allowed': [],
                    'disallowed': [],
                    'sitemaps': []
                }
                
                for line in response.text.split('\n'):
                    if 'Allow:' in line:
                        rules['allowed'].append(line.split('Allow:')[1].strip())
                    elif 'Disallow:' in line:
                        rules['disallowed'].append(line.split('Disallow:')[1].strip())
                    elif 'Sitemap:' in line:
                        rules['sitemaps'].append(line.split('Sitemap:')[1].strip())
                
                return {
                    'status': 'found',
                    'content': response.text,
                    'rules': rules
                }
            return {'status': 'not_found'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def analyze_sitemap(self):
        """Analyze XML sitemap and return its structure."""
        try:
            # First check robots.txt for sitemap
            robots_analysis = self.analyze_robots_txt()
            sitemaps = []
            
            if robots_analysis['status'] == 'found':
                sitemaps.extend(robots_analysis['rules']['sitemaps'])
            
            # Also check common sitemap locations
            common_paths = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap/sitemap.xml']
            
            for path in common_paths:
                try:
                    response = requests.get(f"{self.url}{path}", timeout=self.timeout)
                    if response.status_code == 200:
                        sitemap_dict = xmltodict.parse(response.text)
                        sitemaps.append({
                            'url': f"{self.url}{path}",
                            'content': sitemap_dict
                        })
                except:
                    continue
            
            return {
                'status': 'found' if sitemaps else 'not_found',
                'sitemaps': sitemaps
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def check_mobile_responsiveness(self):
        """Check website's mobile responsiveness."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Test different viewport sizes
            viewports = {
                'mobile': (375, 667),  # iPhone 8
                'tablet': (768, 1024),  # iPad
                'desktop': (1920, 1080)  # Full HD
            }
            
            results = {}
            
            for device, (width, height) in viewports.items():
                driver.set_window_size(width, height)
                driver.get(self.url)
                
                # Take screenshot
                screenshot_path = f"screenshot_{device}.png"
                driver.save_screenshot(screenshot_path)
                
                # Analyze viewport meta tag
                viewport_meta = driver.execute_script(
                    "return document.querySelector('meta[name=\"viewport\"]')"
                    "?.getAttribute('content')")
                
                # Check for mobile-specific elements
                has_media_queries = driver.execute_script(
                    "return window.getComputedStyle(document.documentElement)"
                    ".content.includes('media')")
                
                results[device] = {
                    'viewport_meta': viewport_meta,
                    'has_media_queries': has_media_queries,
                    'screenshot': screenshot_path
                }
            
            driver.quit()
            return results
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def analyze_accessibility(self):
        """Analyze website's accessibility compliance."""
        try:
            # Analyze specific accessibility features
            response = requests.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html5lib')
            
            custom_checks = {
                'has_alt_texts': all(img.has_attr('alt') for img in soup.find_all('img')),
                'has_aria_labels': bool(soup.find_all(attrs={'aria-label': True})),
                'has_skip_links': bool(soup.find('a', href='#main-content')),
                'color_contrast': self._check_color_contrast(soup),
                'keyboard_navigation': self._check_keyboard_navigation(soup)
            }
            
            # Calculate basic accessibility score
            score = 0
            if custom_checks['has_alt_texts']:
                score += 25
            if custom_checks['has_aria_labels']:
                score += 25
            if custom_checks['has_skip_links']:
                score += 25
            if custom_checks['keyboard_navigation']['focusable_elements'] > 0:
                score += 25
            
            return {
                'score': score,
                'custom_checks': custom_checks
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def calculate_seo_score(self):
        """Calculate SEO score based on various factors."""
        try:
            response = requests.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            factors = {
                'title': {
                    'exists': bool(soup.title),
                    'length': len(soup.title.string) if soup.title else 0,
                    'score': 0
                },
                'meta_description': {
                    'exists': bool(soup.find('meta', {'name': 'description'})),
                    'length': len(soup.find('meta', {'name': 'description'})['content'])
                    if soup.find('meta', {'name': 'description'}) else 0,
                    'score': 0
                },
                'headings': {
                    'h1_count': len(soup.find_all('h1')),
                    'h2_count': len(soup.find_all('h2')),
                    'score': 0
                },
                'images': {
                    'total': len(soup.find_all('img')),
                    'with_alt': len([img for img in soup.find_all('img') if img.get('alt')]),
                    'score': 0
                },
                'links': {
                    'internal': len([a for a in soup.find_all('a') if a.get('href') 
                                  and self.domain in a.get('href')]),
                    'external': len([a for a in soup.find_all('a') if a.get('href') 
                                   and self.domain not in a.get('href')]),
                    'score': 0
                }
            }
            
            # Score calculations
            factors['title']['score'] = self._calculate_title_score(factors['title'])
            factors['meta_description']['score'] = self._calculate_meta_score(
                factors['meta_description'])
            factors['headings']['score'] = self._calculate_headings_score(factors['headings'])
            factors['images']['score'] = self._calculate_images_score(factors['images'])
            factors['links']['score'] = self._calculate_links_score(factors['links'])
            
            # Calculate overall score
            total_score = sum(factor['score'] for factor in factors.values()) / len(factors)
            
            return {
                'overall_score': round(total_score, 2),
                'factors': factors
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def capture_screenshot(self, full_page=True):
        """Capture a screenshot of the website."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            driver.get(self.url)
            
            if full_page:
                # Get page dimensions
                height = driver.execute_script("return document.body.scrollHeight")
                width = driver.execute_script("return document.body.scrollWidth")
                driver.set_window_size(width, height)
            
            screenshot_path = "website_screenshot.png"
            driver.save_screenshot(screenshot_path)
            
            # Optimize screenshot
            with Image.open(screenshot_path) as img:
                # Resize if too large
                if img.size[0] > 1920:
                    img = resizeimage.resize_width(img, 1920)
                # Compress
                img.save(screenshot_path, 'PNG', optimize=True)
            
            driver.quit()
            return {
                'status': 'success',
                'path': screenshot_path,
                'size': os.path.getsize(screenshot_path)
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _calculate_title_score(self, title_data):
        """Calculate SEO score for title."""
        score = 0
        if title_data['exists']:
            score += 50
            length = title_data['length']
            if 30 <= length <= 60:
                score += 50
            elif 20 <= length <= 70:
                score += 30
        return score

    def _calculate_meta_score(self, meta_data):
        """Calculate SEO score for meta description."""
        score = 0
        if meta_data['exists']:
            score += 50
            length = meta_data['length']
            if 120 <= length <= 160:
                score += 50
            elif 80 <= length <= 200:
                score += 30
        return score

    def _calculate_headings_score(self, headings_data):
        """Calculate SEO score for headings structure."""
        score = 0
        if headings_data['h1_count'] == 1:
            score += 50
        if headings_data['h2_count'] > 0:
            score += 50
        return score

    def _calculate_images_score(self, images_data):
        """Calculate SEO score for images."""
        score = 0
        if images_data['total'] > 0:
            alt_ratio = images_data['with_alt'] / images_data['total']
            score = alt_ratio * 100
        return score

    def _calculate_links_score(self, links_data):
        """Calculate SEO score for links."""
        score = 0
        total_links = links_data['internal'] + links_data['external']
        if total_links > 0:
            # Prefer a good mix of internal and external links
            if links_data['internal'] > 0:
                score += 50
            if links_data['external'] > 0:
                score += 50
        return score

    def _check_color_contrast(self, soup):
        """Basic color contrast check."""
        # This is a simplified version. A real implementation would need
        # to parse CSS and calculate actual contrast ratios
        return {
            'status': 'manual_check_required',
            'message': 'Color contrast check requires manual verification'
        }

    def _check_keyboard_navigation(self, soup):
        """Check for keyboard navigation support."""
        return {
            'focusable_elements': len(soup.find_all(['a', 'button', 'input', 'select', 'textarea'])),
            'tab_index': len(soup.find_all(attrs={'tabindex': True}))
        }

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
            response = requests.get(self.url, headers=headers, timeout=self.timeout)
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

            # New features
            print(f"\n{Fore.GREEN}🔍 Advanced Analysis:{Style.RESET_ALL}")
            robots_txt_analysis = self.analyze_robots_txt()
            print(f"Robots.txt Analysis: {robots_txt_analysis['status']}")
            sitemap_analysis = self.analyze_sitemap()
            print(f"Sitemap Analysis: {sitemap_analysis['status']}")
            mobile_responsiveness = self.check_mobile_responsiveness()
            print(f"Mobile Responsiveness: {mobile_responsiveness['mobile']['viewport_meta']}")
            accessibility = self.analyze_accessibility()
            print(f"Accessibility: {accessibility['score']}")
            seo_score = self.calculate_seo_score()
            print(f"SEO Score: {seo_score['overall_score']}")
            screenshot = self.capture_screenshot()
            print(f"Screenshot: {screenshot['path']}")

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

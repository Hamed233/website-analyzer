# Website Analyzer 🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/pypi/pyversions/website-analyzer.svg)](https://pypi.org/project/website-analyzer/)

A powerful command-line tool that provides comprehensive analysis and information about websites. Get detailed insights about domain information, security, performance, technologies used, and more.

## 🌟 Features

- 📊 **Basic Information**
  - Status code and response headers
  - IP address resolution
  - Server identification
  - Content type analysis

- 🏢 **Domain Information**
  - Registrar details
  - Creation/expiration dates
  - Nameserver configuration
  - WHOIS data

- 🌐 **DNS Analysis**
  - A and AAAA records
  - MX records for mail servers
  - NS records
  - TXT records for verification

- 🔒 **Security Analysis**
  - SSL/TLS certificate details
  - Security headers inspection
  - HTTPS enforcement check
  - XSS and CSRF protections

- ⚡ **Performance Metrics**
  - Response time measurement
  - Page size calculation
  - Resource counting
  - Load time analysis

- 🔧 **Technology Detection**
  - Web frameworks
  - JavaScript libraries
  - CMS platforms
  - Server technologies

- 🔗 **Link Analysis**
  - Internal/external link counting
  - Broken link detection
  - Redirect chain analysis

- 🔍 **Port Scanning**
  - Common ports status
  - Service detection
  - Security assessment

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager
- nmap (optional, for port scanning)

### Installing nmap

- **macOS**: `brew install nmap`
- **Linux**: `sudo apt-get install nmap`
- **Windows**: Download from [nmap.org](https://nmap.org/download.html)

### Installing Website Analyzer

```bash
# Install from PyPI
pip install website-analyzer

# Or install from source
git clone https://github.com/yourusername/website-analyzer.git
cd website-analyzer
pip install -e .
```

## 💻 Usage

### Basic Usage

```bash
# Analyze a website
website-analyzer example.com

# Analyze with HTTPS
website-analyzer https://example.com
```

### Advanced Options

```bash
# Disable port scanning
website-analyzer example.com --no-port-scan

# Set custom timeout
website-analyzer example.com --timeout 20
```

## 📋 Example Output

```
🌐 Analyzing website: example.com

📊 Basic Information:
Status Code: 200
IP Address: 93.184.216.34
Server: ECS
Content Type: text/html; charset=UTF-8

🔒 SSL/TLS Information:
SSL Version: TLSv1.3
Certificate Expiry: 2024-11-24
...
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🧪 Testing

```bash
# Run tests
python -m unittest discover tests

# Run with coverage
coverage run -m unittest discover tests
coverage report
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and informational purposes only. Always ensure you have permission to scan and analyze websites before using this tool. Some features (like port scanning) may be restricted or prohibited by certain websites or networks.

## 🙏 Acknowledgments

- [Requests](https://requests.readthedocs.io/) for HTTP handling
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing
- [python-whois](https://pypi.org/project/python-whois/) for WHOIS lookups
- [python-nmap](https://pypi.org/project/python-nmap/) for port scanning

## 📧 Contact

Hamed Esam - your.email@example.com

Project Link: [https://github.com/yourusername/website-analyzer](https://github.com/yourusername/website-analyzer)

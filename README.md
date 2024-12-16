# Penetration Testing Toolkit

A comprehensive cybersecurity tool for automated security assessments and vulnerability scanning.

## Features

### 1. Information Gathering
- **DNS Enumeration**: Discover subdomains, DNS records, and zone transfers
- **Port Scanning**: Identify open ports and running services
- **Technology Detection**: Fingerprint web servers, frameworks, and CMS
- **Directory Enumeration**: Discover hidden directories and files
- **SSL/TLS Analysis**: Check certificate validity and security configurations
- **WHOIS Information**: Gather domain registration and ownership details
- **Email Harvesting**: Find email addresses associated with the domain
- **Metadata Extraction**: Analyse documents and images for metadata

### 2. Vulnerability Scanning
- **SQL Injection**: Detect various SQL injection vulnerabilities
  - Union-based injection
  - Error-based injection
  - Time-based blind injection
  - Boolean-based blind injection
- **Cross-Site Scripting (XSS)**
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
  - Template injection
- **Security Misconfigurations**
  - Default credentials
  - Exposed sensitive files
  - Insecure HTTP headers
  - Debug modes enabled
- **Known CVE Detection**: Check for known vulnerabilities in detected software versions

### 3. Manual Testing
- **Directory Traversal**: Test for path traversal vulnerabilities
- **File Upload Testing**: Check for unsafe file upload handling
  - Extension validation bypass
  - Content-type validation
  - File execution tests
- **Access Control**: Test authorisation mechanisms
  - Horizontal privilege escalation
  - Vertical privilege escalation
  - IDOR vulnerabilities
- **Input Validation**: Test form fields and parameters
  - Command injection
  - XML injection
  - Template injection
  - NoSQL injection

### 4. Exploitation
- **Advanced SQL Injection**
  - Database enumeration
  - Data extraction
  - Command execution
- **XSS Exploitation**
  - Cookie stealing
  - Keylogging
  - Phishing payloads
- **File Inclusion**
  - Local File Inclusion (LFI)
  - Remote File Inclusion (RFI)
  - PHP wrapper exploitation
- **Command Injection**
  - OS command execution
  - Reverse shell establishment
  - File system access
- **Authentication Bypass**
  - SQL injection bypass
  - Logic flaws exploitation
  - Session manipulation

### 5. Post-Exploitation
- **Privilege Escalation**
  - Kernel exploits
  - Misconfigured permissions
  - Vulnerable services
- **Network Enumeration**
  - Internal network scanning
  - Service discovery
  - Asset identification
- **Data Exfiltration**
  - Database dumping
  - File system access
  - Configuration retrieval
- **Persistence**
  - Backdoor placement
  - Credential harvesting
  - System monitoring

### 6. Reporting
- **Comprehensive HTML Reports**
  - Executive summary
  - Technical details
  - Proof of concept
  - Remediation steps
  - Risk ratings
- **JSON Export**
  - Machine-readable format
  - Integration-ready data
  - Detailed scan results
- **Database Storage**
  - Historical scan data
  - Vulnerability tracking
  - Progress monitoring
- **Custom Templates**
  - Customisable report formats
  - Brand-specific styling
  - Multiple export options

> **Note**: This tool is designed for educational purposes and authorised security testing only. Always obtain proper permission before testing any system or network.

## Project Structure

```
penetration-testing-toolkit/
├── src/
│   ├── models/         # Database models
│   ├── utils/          # Utility functions
│   └── templates/      # HTML report templates
├── artifacts/
│   ├── logs/           # Log files
│   ├── db/             # Database files
│   └── reports/        # Generated reports
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
```

## Installation

### Method 1: System-wide Installation (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/Sharma-IT/penetration-testing-toolkit.git
cd penetration-testing-toolkit
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install the tool system-wide:
```bash
sudo chmod +x install.sh
sudo ./install.sh
```

This will install the `pentest` command to your system, making it available globally.

### Method 2: Local Installation

1. Clone the repository:
```bash
git clone https://github.com/Sharma-IT/penetration-testing-toolkit.git
cd penetration-testing-toolkit
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

You can use the tool in two ways:

1. If installed system-wide, use the `pentest` command:
```bash
# Run vulnerability scan
pentest -t https://example.com -m scan

# Run information gathering with verbose output
pentest -t 192.168.1.1 -m info -v

# List demo targets
pentest -d
```

2. If installed locally, run the Python script directly:
```bash
python src/main.py -t https://example.com -m scan
```

Available options:
- `-t, --target`: Specify target URL or IP address
- `-m, --mode`: Choose operation mode:
  - `info`: Information Gathering
  - `scan`: Vulnerability Scan
  - `manual`: Manual Testing
  - `exploit`: Exploitation
  - `post`: Post-Exploitation
  - `report`: Generate Report
  - `clear`: Clear Database
- `-d, --demo`: List available demo targets
- `-v, --verbose`: Enable verbose output

### Interactive Mode

To start the interactive menu:
```bash
# If installed system-wide:
pentest

# If installed locally:
python src/main.py
```

## Demo Targets

For safe testing, use these approved demo targets:
- http://demo.testfire.net
- https://public-firing-range.appspot.com
- https://juice-shop.herokuapp.com

## Security Considerations

- Rate limiting implemented
- Safe demo mode with pre-approved targets
- Input validation
- Secure database handling
- Comprehensive logging
- Authorisation required for non-demo targets

## Security Notice

⚠️ **Important**: This tool makes direct HTTP requests to target websites. Your IP address and request details will be visible to the target servers. For anonymity and security:

- Use a VPN service
- Use a proxy server
- Use the Tor network
- Use a dedicated testing environment

Never use this tool without proper authorisation and appropriate security measures in place.

## Dependencies

- Python 3.11+
- SQLAlchemy for database management
- Requests for HTTP operations
- BeautifulSoup4 for HTML parsing
- Jinja2 for report generation
- python-dotenv for environment variables

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the GNU V.3.0 License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational purposes only. Always obtain proper authorisation before testing any target systems.

# Penetration Testing Toolkit

A comprehensive cybersecurity tool for automated security assessments and vulnerability scanning.

## Features

<details open>
<summary><h3>1. Information Gathering</h3></summary>

<details>
<summary><strong>DNS Enumeration</strong></summary>
Discover subdomains, DNS records, and zone transfers
</details>

<details>
<summary><strong>Port Scanning</strong></summary>
Identify open ports and running services
</details>

<details>
<summary><strong>Technology Detection</strong></summary>
Fingerprint web servers, frameworks, and CMS
</details>

<details>
<summary><strong>Directory Enumeration</strong></summary>
Discover hidden directories and files
</details>

<details>
<summary><strong>SSL/TLS Analysis</strong></summary>
Check certificate validity and security configurations
</details>

<details>
<summary><strong>WHOIS Information</strong></summary>
Gather domain registration and ownership details
</details>

<details>
<summary><strong>Email Harvesting</strong></summary>
Find email addresses associated with the domain
</details>

<details>
<summary><strong>Metadata Extraction</strong></summary>
Analyse documents and images for metadata
</details>

</details>

<details>
<summary><h3>2. Vulnerability Scanning</h3></summary>

<details>
<summary><strong>SQL Injection</strong></summary>
Detect various SQL injection vulnerabilities
<ul>
<li>Union-based injection</li>
<li>Error-based injection</li>
<li>Time-based blind injection</li>
<li>Boolean-based blind injection</li>
</ul>
</details>

<details>
<summary><strong>Cross-Site Scripting (XSS)</strong></summary>
<ul>
<li>Reflected XSS</li>
<li>Stored XSS</li>
<li>DOM-based XSS</li>
<li>Template injection</li>
</ul>
</details>

<details>
<summary><strong>Security Misconfigurations</strong></summary>
<ul>
<li>Default credentials</li>
<li>Exposed sensitive files</li>
<li>Insecure HTTP headers</li>
<li>Debug modes enabled</li>
</ul>
</details>

<details>
<summary><strong>Known CVE Detection</strong></summary>
Check for known vulnerabilities in detected software versions
</details>

</details>

<details>
<summary><h3>3. Manual Testing</h3></summary>

<details>
<summary><strong>Directory Traversal</strong></summary>
Test for path traversal vulnerabilities
</details>

<details>
<summary><strong>File Upload Testing</strong></summary>
Check for unsafe file upload handling
<ul>
<li>Extension validation bypass</li>
<li>Content-type validation</li>
<li>File execution tests</li>
</ul>
</details>

<details>
<summary><strong>Access Control</strong></summary>
Test authorisation mechanisms
<ul>
<li>Horizontal privilege escalation</li>
<li>Vertical privilege escalation</li>
<li>IDOR vulnerabilities</li>
</ul>
</details>

<details>
<summary><strong>Input Validation</strong></summary>
Test form fields and parameters
<ul>
<li>Command injection</li>
<li>XML injection</li>
<li>Template injection</li>
<li>NoSQL injection</li>
</ul>
</details>

</details>

<details>
<summary><h3>4. Exploitation</h3></summary>

<details>
<summary><strong>Advanced SQL Injection</strong></summary>
<ul>
<li>Database enumeration</li>
<li>Data extraction</li>
<li>Command execution</li>
</ul>
</details>

<details>
<summary><strong>XSS Exploitation</strong></summary>
<ul>
<li>Cookie stealing</li>
<li>Keylogging</li>
<li>Phishing payloads</li>
</ul>
</details>

<details>
<summary><strong>File Inclusion</strong></summary>
<ul>
<li>Local File Inclusion (LFI)</li>
<li>Remote File Inclusion (RFI)</li>
<li>PHP wrapper exploitation</li>
</ul>
</details>

<details>
<summary><strong>Command Injection</strong></summary>
<ul>
<li>OS command execution</li>
<li>Reverse shell establishment</li>
<li>File system access</li>
</ul>
</details>

<details>
<summary><strong>Authentication Bypass</strong></summary>
<ul>
<li>SQL injection bypass</li>
<li>Logic flaws exploitation</li>
<li>Session manipulation</li>
</ul>
</details>

</details>

<details>
<summary><h3>5. Post-Exploitation</h3></summary>

<details>
<summary><strong>Privilege Escalation</strong></summary>
<ul>
<li>Kernel exploits</li>
<li>Misconfigured permissions</li>
<li>Vulnerable services</li>
</ul>
</details>

<details>
<summary><strong>Network Enumeration</strong></summary>
<ul>
<li>Internal network scanning</li>
<li>Service discovery</li>
<li>Asset identification</li>
</ul>
</details>

<details>
<summary><strong>Data Exfiltration</strong></summary>
<ul>
<li>Database dumping</li>
<li>File system access</li>
<li>Configuration retrieval</li>
</ul>
</details>

<details>
<summary><strong>Persistence</strong></summary>
<ul>
<li>Backdoor placement</li>
<li>Credential harvesting</li>
<li>System monitoring</li>
</ul>
</details>

</details>

<details>
<summary><h3>6. Reporting</h3></summary>

<details>
<summary><strong>Comprehensive HTML Reports</strong></summary>
<ul>
<li>Executive summary</li>
<li>Technical details</li>
<li>Proof of concept</li>
<li>Remediation steps</li>
<li>Risk ratings</li>
</ul>
</details>

<details>
<summary><strong>JSON Export</strong></summary>
<ul>
<li>Machine-readable format</li>
<li>Integration-ready data</li>
<li>Detailed scan results</li>
</ul>
</details>

<details>
<summary><strong>Database Storage</strong></summary>
<ul>
<li>Historical scan data</li>
<li>Vulnerability tracking</li>
<li>Progress monitoring</li>
</ul>
</details>

<details>
<summary><strong>Custom Templates</strong></summary>
<ul>
<li>Customisable report formats</li>
<li>Brand-specific styling</li>
<li>Multiple export options</li>
</ul>
</details>

</details>

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

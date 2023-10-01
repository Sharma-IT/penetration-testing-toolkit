# Penetration Testing Toolkit

The Penetration Testing Toolkit is a robust Python-based tool that combines various techniques and tools to perform thorough security assessments on web applications. From information gathering to vulnerability scanning and manual testing, this toolkit provides a structured and automated approach to identifying vulnerabilities and helping secure digital assets.

# Table of Contents

1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Usage](#usage)
4. [Project Structure](#project-structure)
5. [Security Considerations](#security-considerations)
6. [Disclaimer](#disclaimer)
7. [Contributing](#contributing)
8. [Contact](#contact)
9. [License](#license)

## Features

- **Information gathering** using DNS lookup, Whois lookup, and HTTP header retrieval.
- **Vulnerability scanning** for SQL injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF).
- **Manual testing** for insecure file upload and misconfigured access controls.
- **Exploitation** for SQL injection and Cross-Site Scripting (XSS).
- **Post-exploitation** tasks for collecting credentials and sensitive data.
- **Report generation** in HTML and JSON formats, including detailed findings and vulnerability distribution graphs.

## Prerequisites

- Python 3.x
- Required Python libraries (install using `pip`):
  - `requests`
  - `beautifulsoup4`
  - `jinja2`
  - `matplotlib`

## Usage

1. Clone this repository:

```
git clone https://github.com/Sharma-IT/penetration-testing-toolkit.git
cd penetration-testing-toolkit
```

2. Install the required Python libraries:

```
pip install -r requirements.txt
```

3. Run the script:

```
python main.py
```

4. Follow the prompts and menu options to perform various security assessment tasks.

## Project Structure

- `main.py`: The main Python script that orchestrates the penetration testing tasks.
- `templates/`: Folder containing HTML template files for report generation.
- `reports/`: Folder where generated reports will be stored.
- `payload.php`: PHP payload for exploitation. Ensure proper usage and security measures.
- `database.db`: SQLite database for storing results and report details.

## Security Considerations

- Use this toolkit responsibly and only on systems you have explicit permission to assess.
- Always follow ethical hacking guidelines and obtain proper authorisation before conducting any penetration testing.
- Securely store sensitive data and credentials used for testing.
- Regularly update and patch your testing environment to prevent unintended consequences.

## Disclaimer

This toolkit is provided for educational and ethical purposes only. I am are not responsible for any misuse or damage caused by its use.

## Contributing

Pull requests are welcomed. For major changes, please open an issue first to discuss what you would like to change.

## Contact

Shubham Sharma - [My LinkedIn](https://www.linkedin.com/in/sharma-it/) - shubhamsharma.emails@gmail.com.

## License

This project is licensed under the GPL 3.0 License - see the [LICENSE](LICENSE) file for details.
